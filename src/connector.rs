use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Error, bail};
use arrow::array::StringArray;
use async_trait::async_trait;
use autoschematic_core::{
    connector::{
        Connector, ConnectorOp, ConnectorOutbox, FilterResponse, GetResourceResponse, OpExecResponse, PlanResponseElement,
        Resource, ResourceAddress,
    },
    connector_op,
    diag::{Diagnostic, DiagnosticPosition, DiagnosticResponse, DiagnosticSeverity, DiagnosticSpan},
    get_resource_response,
    util::{ron_check_eq, ron_check_syntax},
};
use base64::prelude::*;
use indexmap::IndexSet;
use snowflake_api::SnowflakeApi;
use tokio::sync::Mutex;

use crate::{
    addr::SnowflakeResourceAddress,
    op::*,
    resource::*,
    util::sql::{self, build_alter_role_sql, build_create_role_sql},
};
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

impl SnowflakeConnector {}

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
            addr => match &addr {
                SnowflakeResourceAddress::Warehouse { name } => self.get_ddl("WAREHOUSE", &name).await,
                SnowflakeResourceAddress::Database { name } => self.get_ddl("DATABASE", &name).await,
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
            },
        }
    }

    async fn plan(
        &self,
        addr: &Path,
        current: Option<Vec<u8>>,
        desired: Option<Vec<u8>>,
    ) -> Result<Vec<PlanResponseElement>, anyhow::Error> {
        tracing::info!("plan {:?} -? {:?}", current, desired);
        let addr = SnowflakeResourceAddress::from_path(addr)?;

        let mut res = Vec::new();

        match &addr {
            SnowflakeResourceAddress::Database { .. } => match (current, desired) {
                (None, None) => Ok(Vec::new()),
                (Some(_), None) => Ok(Vec::new()),
                (Some(_), Some(_)) => Ok(Vec::new()),
                (None, Some(definition)) => {
                    let _definition = SQLDefinition::from_bytes(&addr, &definition);
                    let _api = self.get_api(None, None).await?;
                    Ok(vec![])
                }
            },
            SnowflakeResourceAddress::User { name } => {
                match (current, desired) {
                    (None, None) => {}
                    (None, Some(new_user_bytes)) => {
                        // Create new user
                        let new_user: SnowflakeUser = SnowflakeUser::from_bytes(&addr, &new_user_bytes)?;
                        let roles_to_grant = new_user.granted_roles.clone();
                        res.push(connector_op!(
                            SnowflakeConnectorOp::CreateUser(new_user),
                            format!("Create Snowflake user `{}`", name)
                        ));
                        // Grant roles after creation
                        for role in roles_to_grant {
                            res.push(connector_op!(
                                SnowflakeConnectorOp::GrantRoleToUser(role.clone()),
                                format!("Grant role `{}` to user `{}`", role, name)
                            ));
                        }
                    }
                    (Some(_old_user_bytes), None) => {
                        // Drop user
                        res.push(connector_op!(
                            SnowflakeConnectorOp::DropUser,
                            format!("Drop Snowflake user `{}`", name)
                        ));
                    }
                    (Some(old_user_bytes), Some(new_user_bytes)) => {
                        // Alter user if different
                        let old_user: SnowflakeUser = SnowflakeUser::from_bytes(&addr, &old_user_bytes)?;
                        let new_user: SnowflakeUser = SnowflakeUser::from_bytes(&addr, &new_user_bytes)?;

                        // Check if non-grant properties changed
                        let old_props = SnowflakeUser {
                            granted_roles: IndexSet::new(),
                            ..old_user.clone()
                        };
                        let new_props = SnowflakeUser {
                            granted_roles: IndexSet::new(),
                            ..new_user.clone()
                        };
                        if old_props != new_props {
                            res.push(connector_op!(
                                SnowflakeConnectorOp::AlterUser(old_user.clone(), new_user.clone()),
                                format!("Alter Snowflake user `{}`", name)
                            ));
                        }

                        // Handle role grant changes
                        for role in new_user.granted_roles.difference(&old_user.granted_roles) {
                            res.push(connector_op!(
                                SnowflakeConnectorOp::GrantRoleToUser(role.clone()),
                                format!("Grant role `{}` to user `{}`", role, name)
                            ));
                        }
                        for role in old_user.granted_roles.difference(&new_user.granted_roles) {
                            res.push(connector_op!(
                                SnowflakeConnectorOp::RevokeRoleFromUser(role.clone()),
                                format!("Revoke role `{}` from user `{}`", role, name)
                            ));
                        }
                    }
                }
                Ok(res)
            }
            SnowflakeResourceAddress::Role { name } => {
                match (current, desired) {
                    (None, None) => {}
                    (None, Some(new_role_bytes)) => {
                        // Create new role
                        let new_role: SnowflakeRole = SnowflakeRole::from_bytes(&addr, &new_role_bytes)?;
                        let roles_to_grant = new_role.granted_roles.clone();
                        res.push(connector_op!(
                            SnowflakeConnectorOp::CreateRole(new_role),
                            format!("Create Snowflake role `{}`", name)
                        ));
                        // Grant roles after creation
                        for role in roles_to_grant {
                            res.push(connector_op!(
                                SnowflakeConnectorOp::GrantRoleToRole(role.clone()),
                                format!("Grant role `{}` to role `{}`", role, name)
                            ));
                        }
                    }
                    (Some(_old_role_bytes), None) => {
                        // Drop role
                        res.push(connector_op!(
                            SnowflakeConnectorOp::DropRole,
                            format!("Drop Snowflake role `{}`", name)
                        ));
                    }
                    (Some(old_role_bytes), Some(new_role_bytes)) => {
                        // Alter role if different
                        let old_role: SnowflakeRole = SnowflakeRole::from_bytes(&addr, &old_role_bytes)?;
                        let new_role: SnowflakeRole = SnowflakeRole::from_bytes(&addr, &new_role_bytes)?;

                        // Check if non-grant properties changed (just comment)
                        if old_role.comment != new_role.comment {
                            res.push(connector_op!(
                                SnowflakeConnectorOp::AlterRole(old_role.clone(), new_role.clone()),
                                format!("Alter Snowflake role `{}`", name)
                            ));
                        }

                        // Handle role grant changes
                        for role in new_role.granted_roles.difference(&old_role.granted_roles) {
                            res.push(connector_op!(
                                SnowflakeConnectorOp::GrantRoleToRole(role.clone()),
                                format!("Grant role `{}` to role `{}`", role, name)
                            ));
                        }
                        for role in old_role.granted_roles.difference(&new_role.granted_roles) {
                            res.push(connector_op!(
                                SnowflakeConnectorOp::RevokeRoleFromRole(role.clone()),
                                format!("Revoke role `{}` from role `{}`", role, name)
                            ));
                        }
                    }
                }
                Ok(res)
            }
            _ => Ok(vec![]),
        }
    }

    async fn op_exec(&self, addr: &Path, op: &str) -> Result<OpExecResponse, anyhow::Error> {
        let op = SnowflakeConnectorOp::from_str(op)?;
        let addr = SnowflakeResourceAddress::from_path(addr)?;

        match addr {
            SnowflakeResourceAddress::Warehouse { name } => {
                let api = self.get_api(None, None).await?;
                match &op {
                    SnowflakeConnectorOp::Execute(def) => {
                        let _res = api.exec(&def.statement.to_string()).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", def.statement)),
                        })
                    }
                    SnowflakeConnectorOp::Delete => {
                        let statement = format!("DROP WAREHOUSE {};", name);
                        let _res = api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", statement)),
                        })
                    }
                    _ => bail!("Invalid operation for Warehouse address"),
                }
            }
            SnowflakeResourceAddress::Database { name } => {
                let api = self.get_api(None, None).await?;
                match &op {
                    SnowflakeConnectorOp::Execute(def) => {
                        let _res = api.exec(&def.statement.to_string()).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", def.statement)),
                        })
                    }
                    SnowflakeConnectorOp::Delete => {
                        let statement = format!("DROP DATABASE {};", name);
                        let _res = api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", statement)),
                        })
                    }
                    _ => bail!("Invalid operation for Database address"),
                }
            }
            SnowflakeResourceAddress::Schema { database, name } => {
                let api = self.get_api(Some(&database), None).await?;
                match &op {
                    SnowflakeConnectorOp::Execute(def) => {
                        let _res = api.exec(&def.statement.to_string()).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", def.statement)),
                        })
                    }
                    SnowflakeConnectorOp::Delete => {
                        let statement = format!("DROP SCHEMA {}.{};", database, name);
                        let _res = api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", statement)),
                        })
                    }
                    _ => bail!("Invalid operation for Schema address"),
                }
            }
            SnowflakeResourceAddress::Table { database, schema, name } => {
                let api = self.get_api(Some(&database), Some(&schema)).await?;
                match &op {
                    SnowflakeConnectorOp::Execute(def) => {
                        let _res = api.exec(&def.statement.to_string()).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", def.statement)),
                        })
                    }
                    SnowflakeConnectorOp::Delete => {
                        let statement = format!("DROP TABLE {}.{}.{};", database, schema, name);
                        let _res = api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", statement)),
                        })
                    }
                    _ => bail!("Invalid operation for Table address"),
                }
            }
            SnowflakeResourceAddress::User { name } => {
                let api = self.get_api(None, None).await?;
                match op {
                    SnowflakeConnectorOp::CreateUser(user) => {
                        let statement = sql::build_create_user_sql(&name, &user);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Created Snowflake user `{}`", name)),
                        })
                    }
                    SnowflakeConnectorOp::AlterUser(_old_user, new_user) => {
                        let statement = sql::build_alter_user_sql(&name, &new_user);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Altered Snowflake user `{}`", name)),
                        })
                    }
                    SnowflakeConnectorOp::DropUser => {
                        let statement = format!("DROP USER {};", name);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Dropped Snowflake user `{}`", name)),
                        })
                    }
                    SnowflakeConnectorOp::GrantRoleToUser(role_name) => {
                        let statement = format!("GRANT ROLE {} TO USER {};", role_name, name);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Granted role `{}` to user `{}`", role_name, name)),
                        })
                    }
                    SnowflakeConnectorOp::RevokeRoleFromUser(role_name) => {
                        let statement = format!("REVOKE ROLE {} FROM USER {};", role_name, name);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Revoked role `{}` from user `{}`", role_name, name)),
                        })
                    }
                    _ => bail!("Invalid operation for User address"),
                }
            }
            SnowflakeResourceAddress::Role { name } => {
                let api = self.get_api(None, None).await?;
                match op {
                    SnowflakeConnectorOp::CreateRole(role) => {
                        let statement = build_create_role_sql(&name, &role);
                        api.exec(&statement).await?;

                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Created Snowflake role `{}`", name)),
                        })
                    }
                    SnowflakeConnectorOp::AlterRole(_old_role, new_role) => {
                        // Update comment (grants are handled as separate ops)
                        let statement = build_alter_role_sql(&name, &new_role);
                        api.exec(&statement).await?;

                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Altered Snowflake role `{}`", name)),
                        })
                    }
                    SnowflakeConnectorOp::DropRole => {
                        let statement = format!("DROP ROLE {};", name);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Dropped Snowflake role `{}`", name)),
                        })
                    }
                    SnowflakeConnectorOp::GrantRoleToRole(role_name) => {
                        let statement = format!("GRANT ROLE {} TO ROLE {};", role_name, name);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Granted role `{}` to role `{}`", role_name, name)),
                        })
                    }
                    SnowflakeConnectorOp::RevokeRoleFromRole(role_name) => {
                        let statement = format!("REVOKE ROLE {} FROM ROLE {};", role_name, name);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Revoked role `{}` from role `{}`", role_name, name)),
                        })
                    }
                    _ => bail!("Invalid operation for Role address"),
                }
            }
        }
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
