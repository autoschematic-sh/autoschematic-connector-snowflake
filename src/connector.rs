use std::{
    collections::BTreeSet,
    env,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Error};
use async_trait::async_trait;
use autoschematic_core::{
    connector::{
        Connector, ConnectorOp, ConnectorOutbox, DocIdent, FilterResponse, GetDocResponse, GetResourceResponse, OpExecResponse,
        PlanResponseElement, Resource, ResourceAddress, SkeletonResponse,
    },
    connector_op,
    diag::{Diagnostic, DiagnosticPosition, DiagnosticResponse, DiagnosticSeverity, DiagnosticSpan},
    doc_dispatch, get_resource_response, skeleton,
    util::{ron_check_eq, ron_check_syntax},
};
use base64::prelude::*;
use indexmap::{IndexMap, IndexSet};
use snowflake_api::SnowflakeApi;
use tokio::sync::Mutex;

use crate::{
    addr::SnowflakeResourceAddress,
    op::*,
    resource::*,
};

mod op_exec;
mod plan;

/// Configuration for the Snowflake connector, loaded during init().
#[derive(Clone)]
pub struct SnowflakeConnectorConfig {
    pub account: String,
    pub user: String,
    pub role: String,
    pub warehouse: String,
    pub private_key: String,
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
        Some(self.config.lock().await.as_ref()?.role.clone())
    }

    fn flatten_grants(grants: &IndexMap<String, Vec<ObjectType>>) -> BTreeSet<(String, ObjectType)> {
        grants
            .iter()
            .flat_map(|(privilege, object_types)| {
                object_types
                    .iter()
                    .cloned()
                    .map(|object_type| (privilege.clone(), object_type))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn user_properties_only(user: &SnowflakeUser) -> SnowflakeUser {
        SnowflakeUser {
            granted_roles: IndexSet::new(),
            grants: IndexMap::new(),
            ..user.clone()
        }
    }

    fn role_properties_only(role: &SnowflakeRole) -> SnowflakeRole {
        SnowflakeRole {
            owner: None,
            granted_roles: IndexSet::new(),
            grants: IndexMap::new(),
            future_grants: IndexMap::new(),
            ..role.clone()
        }
    }

    fn describe_object_type(object_type: &ObjectType, future: bool) -> String {
        let (kind, name) = match object_type {
            ObjectType::ACCOUNT(_) => ("ACCOUNT", ""),
            ObjectType::CATALOG_INTEGRATION(name) => ("CATALOG INTEGRATION", name.as_str()),
            ObjectType::COMPUTE_POOL(name) => ("COMPUTE POOL", name.as_str()),
            ObjectType::DATABASE(name) => ("DATABASE", name.as_str()),
            ObjectType::DATABASE_ROLE(name) => ("DATABASE ROLE", name.as_str()),
            ObjectType::DYNAMIC_TABLE(name) => ("DYNAMIC TABLE", name.as_str()),
            ObjectType::EVENT_TABLE(name) => ("EVENT TABLE", name.as_str()),
            ObjectType::EXTERNAL_VOLUME(name) => ("EXTERNAL VOLUME", name.as_str()),
            ObjectType::FUNCTION(name) => ("FUNCTION", name.as_str()),
            ObjectType::IMAGE_REPOSITORY(name) => ("IMAGE REPOSITORY", name.as_str()),
            ObjectType::MANAGED_ACCOUNT(name) => ("MANAGED ACCOUNT", name.as_str()),
            ObjectType::NETWORK_POLICY(name) => ("NETWORK POLICY", name.as_str()),
            ObjectType::NOTEBOOK(name) => ("NOTEBOOK", name.as_str()),
            ObjectType::NOTIFICATION_INTEGRATION(name) => ("NOTIFICATION INTEGRATION", name.as_str()),
            ObjectType::PIPE(name) => ("PIPE", name.as_str()),
            ObjectType::PROCEDURE(name) => ("PROCEDURE", name.as_str()),
            ObjectType::ROLE(name) => ("ROLE", name.as_str()),
            ObjectType::SCHEMA(name) => ("SCHEMA", name.as_str()),
            ObjectType::SERVICE(name) => ("SERVICE", name.as_str()),
            ObjectType::STAGE(name) => ("STAGE", name.as_str()),
            ObjectType::STREAM(name) => ("STREAM", name.as_str()),
            ObjectType::TABLE(name) => ("TABLE", name.as_str()),
            ObjectType::TASK(name) => ("TASK", name.as_str()),
            ObjectType::USER_DEFINED_FUNCTION(name) => ("FUNCTION", name.as_str()),
            ObjectType::VIEW(name) => ("VIEW", name.as_str()),
            ObjectType::WAREHOUSE(name) => ("WAREHOUSE", name.as_str()),
        };

        if name.is_empty() {
            if future { format!("future {kind}") } else { kind.to_string() }
        } else if future {
            format!("future {kind} `{name}`")
        } else {
            format!("{kind} `{name}`")
        }
    }

    fn extend_privilege_plan(
        res: &mut Vec<PlanResponseElement>,
        target_kind: PrivilegeTargetKind,
        target_name: &str,
        old_grants: &IndexMap<String, Vec<ObjectType>>,
        new_grants: &IndexMap<String, Vec<ObjectType>>,
        future: bool,
    ) -> anyhow::Result<()> {
        let old_specs = Self::flatten_grants(old_grants);
        let new_specs = Self::flatten_grants(new_grants);

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
                    Self::describe_object_type(object_type, future),
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
                    Self::describe_object_type(object_type, future),
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
        let account = env::var("SF_ACCOUNT").context("SF_ACCOUNT env var not set!")?;
        let user = env::var("SF_USER").context("SF_USER env var not set!")?;
        let role = env::var("SF_ROLE").context("SF_ROLE env var not set!")?;
        let warehouse = env::var("SF_WAREHOUSE").context("SF_WAREHOUSE env var not set!")?;
        let private_key_base64 = env::var("SF_PRIVATE_KEY_BASE64");
        let private_key_path = env::var("SF_PRIVATE_KEY_PATH");

        let private_key = match (private_key_base64, private_key_path) {
            (Ok(_), Ok(_)) => Err(Error::msg(
                "Ambiguous: Only one of SF_PRIVATE_KEY_BASE64 and SF_PRIVATE_KEY_PATH can be set!",
            )),
            (Ok(private_key_base64), Err(_)) => {
                let private_key = BASE64_STANDARD
                    .decode(private_key_base64)
                    .context("Failed to decode SF_PRIVATE_KEY_BASE64")?;
                Ok(String::from_utf8(private_key).context("SF_PRIVATE_KEY_BASE64 is not valid UTF-8")?)
            }
            (Err(_), Ok(private_key_path)) => std::fs::read_to_string(&private_key_path)
                .with_context(|| format!("Failed to read private key from {}", private_key_path)),
            (Err(_), Err(_)) => Err(Error::msg("SF_PRIVATE_KEY_BASE64 or SF_PRIVATE_KEY_PATH not set!")),
        }?;

        let config = SnowflakeConnectorConfig {
            account,
            user,
            role,
            warehouse,
            private_key,
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

    async fn list(&self, _subpath: &Path) -> Result<Vec<PathBuf>, anyhow::Error> {
        let api = self.get_api(None, None).await?;
        let mut results = Vec::new();

        for name in SnowflakeConnector::list_warehouses(&api).await? {
            results.push(SnowflakeResourceAddress::Warehouse { name }.to_path_buf());
        }

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

        for name in SnowflakeConnector::list_users(&api).await? {
            results.push(SnowflakeResourceAddress::User { name }.to_path_buf());
        }

        for name in SnowflakeConnector::list_roles(&api).await? {
            results.push(SnowflakeResourceAddress::Role { name }.to_path_buf());
        }

        Ok(results)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flatten_grants_is_order_independent() {
        let mut grants = IndexMap::new();
        grants.insert(
            "USAGE".into(),
            vec![
                ObjectType::SCHEMA("RAW.PUBLIC".into()),
                ObjectType::DATABASE("RAW".into()),
                ObjectType::SCHEMA("RAW.PUBLIC".into()),
            ],
        );
        grants.insert("SELECT".into(), vec![ObjectType::TABLE("RAW.PUBLIC.EVENTS".into())]);

        let flattened = SnowflakeConnector::flatten_grants(&grants);

        assert_eq!(flattened.len(), 3);
        assert!(flattened.contains(&("USAGE".into(), ObjectType::DATABASE("RAW".into()))));
        assert!(flattened.contains(&("USAGE".into(), ObjectType::SCHEMA("RAW.PUBLIC".into()))));
        assert!(flattened.contains(&("SELECT".into(), ObjectType::TABLE("RAW.PUBLIC.EVENTS".into()))));
    }
}
