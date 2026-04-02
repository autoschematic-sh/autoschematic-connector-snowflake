use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use async_trait::async_trait;
use autoschematic_core::{
    connector::{
        Connector, ConnectorOp, ConnectorOutbox, DocIdent, FilterResponse, GetDocResponse, GetResourceResponse, OpExecResponse,
        PlanResponseElement, Resource, ResourceAddress, SkeletonResponse,
    },
    connector_op,
    diag::{Diagnostic, DiagnosticPosition, DiagnosticResponse, DiagnosticSeverity, DiagnosticSpan},
    doc_dispatch, get_resource_response,
    glob::addr_matches_filter,
    skeleton,
    util::{ron_check_eq, ron_check_syntax},
};
use indexmap::IndexMap;
use snowflake_api::SnowflakeApi;
use tokio::sync::Mutex;

use crate::{
    addr::SnowflakeResourceAddress,
    config::{load_legacy_env_connector_config, load_snowflake_cli_connector_config},
    op::*,
    resource::*,
    util,
};

mod op_exec;
mod plan;

/// Internal config for the Snowflake connector, built during init().
#[derive(Clone)]
pub struct SnowflakeConnectorConfig {
    pub account: String,
    pub user: String,
    pub role: Option<String>,
    pub warehouse: Option<String>,
    pub auth: SnowflakeConnectorAuth,
}

#[derive(Clone)]
pub enum SnowflakeConnectorAuth {
    Password(String),
    PrivateKey(String),
}

pub struct SnowflakeConnector {
    pub config: Mutex<Option<SnowflakeConnectorConfig>>,
    pub api: Mutex<Option<Arc<SnowflakeApi>>>,
}

#[derive(Clone, Copy)]
pub enum PrivilegeTargetKind {
    User,
    Role,
}

impl PrivilegeTargetKind {
    pub fn display_name(self) -> &'static str {
        match self {
            PrivilegeTargetKind::User => "user",
            PrivilegeTargetKind::Role => "role",
        }
    }
}

impl SnowflakeConnector {
    async fn current_session_role(&self) -> Option<String> {
        self.config.lock().await.as_ref()?.role.clone()
    }

    fn extend_privilege_plan(
        res: &mut Vec<PlanResponseElement>,
        target_kind: PrivilegeTargetKind,
        target_name: &str,
        old_grants: &IndexMap<String, Vec<ObjectType>>,
        new_grants: &IndexMap<String, Vec<ObjectType>>,
        future: bool,
    ) -> anyhow::Result<()> {
        let old_specs = util::flatten_grants(old_grants);
        let new_specs = util::flatten_grants(new_grants);

        // Compute the privileges to grant...
        for (privilege, object_type) in new_specs.difference(&old_specs) {
            res.push(connector_op!(
                SnowflakeConnectorOp::GrantPrivilege {
                    privilege: privilege.clone(),
                    object_type: object_type.clone(),
                    future,
                },
                format!(
                    "Grant {} on {} to {} `{}`",
                    privilege,
                    util::describe_object_type(object_type, future),
                    target_kind.display_name(),
                    target_name
                )
            ));
        }

        // Compute the privileges to revoke...
        for (privilege, object_type) in old_specs.difference(&new_specs) {
            res.push(connector_op!(
                SnowflakeConnectorOp::RevokePrivilege {
                    privilege: privilege.clone(),
                    object_type: object_type.clone(),
                    future,
                },
                format!(
                    "Revoke {} on {} from {} `{}`",
                    privilege,
                    util::describe_object_type(object_type, future),
                    target_kind.display_name(),
                    target_name
                )
            ));
        }

        Ok(())
    }
}

#[async_trait]
impl Connector for SnowflakeConnector {
    async fn new(_name: &str, _prefix: &Path, _outbox: ConnectorOutbox) -> Result<Arc<dyn Connector>, anyhow::Error>
    where
        Self: Sized,
    {
        Ok(Arc::new(SnowflakeConnector {
            config: Mutex::new(None),
            api: Mutex::new(None),
        }))
    }

    async fn init(&self) -> anyhow::Result<()> {
        let config = match load_snowflake_cli_connector_config()? {
            Some(config) => config,
            None => load_legacy_env_connector_config()
                .context("Failed to load Snowflake CLI config and no legacy SF_* credentials were available")?,
        };

        *self.config.lock().await = Some(config);
        Ok(())
    }

    async fn filter(&self, addr: &Path) -> Result<FilterResponse, anyhow::Error> {
        if let Ok(_addr) = SnowflakeResourceAddress::from_path(addr) {
            Ok(FilterResponse::Resource)
        } else {
            Ok(FilterResponse::None)
        }
    }

    async fn list(&self, subpath: &Path) -> Result<Vec<PathBuf>, anyhow::Error> {
        let api = self.get_api(None, None).await?;
        let mut results = Vec::new();

        if addr_matches_filter(&PathBuf::from("snowflake/warehouses"), subpath) {
            for name in SnowflakeConnector::list_warehouses(&api).await? {
                results.push(SnowflakeResourceAddress::Warehouse { name }.to_path_buf());
            }
        }

        if addr_matches_filter(&PathBuf::from("snowflake/databases"), subpath) {
            for database in SnowflakeConnector::list_databases(&api).await? {
                if database == "SNOWFLAKE" {
                    continue;
                }

                results.push(SnowflakeResourceAddress::Database { name: database.clone() }.to_path_buf());

                for schema_name in SnowflakeConnector::list_schemas(&api, &database).await? {
                    results.push(
                        SnowflakeResourceAddress::Schema {
                            database: database.clone(),
                            name: schema_name.clone(),
                        }
                        .to_path_buf(),
                    );
                    for table_name in SnowflakeConnector::list_tables(&api, &database, &schema_name).await? {
                        results.push(
                            SnowflakeResourceAddress::Table {
                                database: database.clone(),
                                schema: schema_name.clone(),
                                name: table_name.clone(),
                            }
                            .to_path_buf(),
                        );
                    }
                }
            }
        }

        if addr_matches_filter(&PathBuf::from("snowflake/users"), subpath) {
            for name in SnowflakeConnector::list_users(&api).await? {
                results.push(SnowflakeResourceAddress::User { name }.to_path_buf());
            }
        }

        if addr_matches_filter(&PathBuf::from("snowflake/roles"), subpath) {
            for name in SnowflakeConnector::list_roles(&api).await? {
                results.push(SnowflakeResourceAddress::Role { name }.to_path_buf());
            }
        }

        Ok(results)
    }

    async fn subpaths(&self) -> anyhow::Result<Vec<PathBuf>> {
        Ok(vec![
            "snowflake/users".into(),
            "snowflake/roles".into(),
            "snowflake/databases".into(),
            "snowflake/warehouses".into(),
        ])
    }

    async fn get(&self, addr: &Path) -> Result<Option<GetResourceResponse>, anyhow::Error> {
        let addr = SnowflakeResourceAddress::from_path(addr)?;
        match &addr {
            SnowflakeResourceAddress::Warehouse { name } => self.get_ddl("WAREHOUSE", name).await,
            SnowflakeResourceAddress::Database { name } => self.get_ddl("DATABASE", name).await,
            SnowflakeResourceAddress::Schema { database, name } => {
                self.get_ddl("SCHEMA", &format!("{}.{}", database, name)).await
            }
            SnowflakeResourceAddress::Table { database, schema, name } => {
                self.get_ddl("TABLE", &format!("{}.{}.{}", database, schema, name)).await
            }
            SnowflakeResourceAddress::FileFormat { database, schema, name } => {
                self.get_ddl("FILE_FORMAT", &format!("{}.{}.{}", database, schema, name))
                    .await
            }
            SnowflakeResourceAddress::User { name } => {
                let api = self.get_api(None, None).await?;
                if let Some(user) = SnowflakeConnector::get_user(&api, name).await? {
                    get_resource_response!(user)
                } else {
                    Ok(None)
                }
            }
            SnowflakeResourceAddress::Role { name } => {
                let api = self.get_api(None, None).await?;
                if let Some(role) = SnowflakeConnector::get_role(&api, name).await? {
                    get_resource_response!(role)
                } else {
                    Ok(None)
                }
            }
        }
    }

    async fn plan(
        &self,
        addr: &Path,
        current: Option<Vec<u8>>,
        desired: Option<Vec<u8>>,
    ) -> Result<Vec<PlanResponseElement>, anyhow::Error> {
        self.do_plan(addr, current, desired).await
    }

    async fn op_exec(&self, addr: &Path, op: &str) -> Result<OpExecResponse, anyhow::Error> {
        self.do_op_exec(addr, op).await
    }

    async fn get_docstring(&self, _addr: &Path, ident: DocIdent) -> anyhow::Result<Option<GetDocResponse>> {
        doc_dispatch!(ident, [SnowflakeUser, SnowflakeRole])
    }

    async fn eq(&self, addr: &Path, a: &[u8], b: &[u8]) -> anyhow::Result<bool> {
        let parsed_addr = SnowflakeResourceAddress::from_path(addr)?;

        match parsed_addr {
            // RON-based resources (users, roles)
            SnowflakeResourceAddress::User { .. } => ron_check_eq::<SnowflakeUser>(a, b),
            SnowflakeResourceAddress::Role { .. } => ron_check_eq::<SnowflakeRole>(a, b),
            // SQL-based resources (warehouses, databases, schemas, tables)
            _ => Ok(a == b),
        }
    }

    async fn get_skeletons(&self) -> Result<Vec<SkeletonResponse>, anyhow::Error> {
        let mut res = Vec::new();

        res.push(skeleton!(
            SnowflakeResourceAddress::User { name: "[name]".into() },
            SnowflakeUser {
                first_name: Some("first_name".into()),
                last_name: Some("last_name".into()),
                email: Some("email".into()),
                comment: Some("comment".into()),
                ..Default::default()
            }
        ));

        res.push(skeleton!(
            SnowflakeResourceAddress::Role { name: "[name]".into() },
            SnowflakeRole {
                owner: Some("ACCOUNTADMIN".into()),
                comment: Some("comment".into()),
                ..Default::default()
            }
        ));
        Ok(res)
    }

    async fn diag(&self, addr: &Path, a: &[u8]) -> Result<Option<DiagnosticResponse>, anyhow::Error> {
        let parsed_addr = SnowflakeResourceAddress::from_path(addr)?;

        match parsed_addr {
            // RON-based resources (users, roles)
            SnowflakeResourceAddress::User { .. } => ron_check_syntax::<SnowflakeUser>(a),
            SnowflakeResourceAddress::Role { .. } => ron_check_syntax::<SnowflakeRole>(a),
            // SQL-based resources (warehouses, databases, schemas, tables)
            _ => {
                let snowflake_dialect = sqlparser::dialect::SnowflakeDialect;
                let ast = sqlparser::parser::Parser::parse_sql(&snowflake_dialect, str::from_utf8(a)?);
                match ast {
                    Ok(_) => Ok(Some(DiagnosticResponse { diagnostics: Vec::new() })),
                    Err(e) => match e {
                        sqlparser::parser::ParserError::TokenizerError(e) => Ok(Some(DiagnosticResponse {
                            diagnostics: vec![Diagnostic {
                                severity: DiagnosticSeverity::ERROR as u8,
                                span: DiagnosticSpan {
                                    start: DiagnosticPosition { line: 1, col: 1 },
                                    end: DiagnosticPosition { line: 1, col: 1 },
                                },
                                message: e,
                            }],
                        })),
                        sqlparser::parser::ParserError::ParserError(e) => Ok(Some(DiagnosticResponse {
                            diagnostics: vec![Diagnostic {
                                severity: DiagnosticSeverity::ERROR as u8,
                                span: DiagnosticSpan {
                                    start: DiagnosticPosition { line: 1, col: 1 },
                                    end: DiagnosticPosition { line: 1, col: 1 },
                                },
                                message: e,
                            }],
                        })),
                        sqlparser::parser::ParserError::RecursionLimitExceeded => Ok(Some(DiagnosticResponse {
                            diagnostics: vec![Diagnostic {
                                severity: DiagnosticSeverity::ERROR as u8,
                                span: DiagnosticSpan {
                                    start: DiagnosticPosition { line: 1, col: 1 },
                                    end: DiagnosticPosition { line: 1, col: 1 },
                                },
                                message: "Recursion limit exceeded".into(),
                            }],
                        })),
                    },
                }
            }
        }
    }
}
