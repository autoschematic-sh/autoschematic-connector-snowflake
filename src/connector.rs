use std::{
    collections::{HashMap, HashSet},
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
    error_util::invalid_addr_path,
    get_resource_response,
    util::{PrettyConfig, RON, ron_check_syntax},
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use snowflake_api::{QueryResult, SnowflakeApi};
use sqlparser::ast::{DescribeAlias, Statement};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Error, Debug)]
enum SnowflakeConnectorError {
    #[error("We were expecting a JSON result, but got Arrow")]
    UnexpectedArrowResult,
    #[error("We were expecting a JSON result, but got an empty one")]
    UnexpectedEmptyResult,
}

/// Configuration for the Snowflake connector, loaded during init().
#[derive(Clone)]
pub struct SnowflakeConnectorConfig {
    account: String,
    user: String,
    role: String,
    warehouse: String,
    private_key: String,
}

pub struct SnowflakeConnector {
    config: Mutex<Option<SnowflakeConnectorConfig>>,
    api: Mutex<Option<Arc<SnowflakeApi>>>,
}

type Name = String;
type DatabaseName = String;
type SchemaName = String;

#[derive(Clone, Debug)]
pub enum SnowflakeResourceAddress {
    Warehouse(String),
    Database(Name),
    Schema(DatabaseName, Name),
    Table(DatabaseName, SchemaName, Name),
    // RBAC resources
    User(Name),
    Role(Name),
}

fn strip_sql_suffix(s: &str) -> String {
    s.strip_suffix(".sql").unwrap().to_string()
}

fn strip_ron_suffix(s: &str) -> String {
    s.strip_suffix(".ron").unwrap().to_string()
}

impl ResourceAddress for SnowflakeResourceAddress {
    fn to_path_buf(&self) -> std::path::PathBuf {
        match self {
            SnowflakeResourceAddress::Warehouse(name) => PathBuf::from(format!("snowflake/warehouses/{}.sql", name)),
            SnowflakeResourceAddress::Database(name) => PathBuf::from(format!("snowflake/databases/{}/database.sql", name)),
            SnowflakeResourceAddress::Schema(database_name, name) => {
                PathBuf::from(format!("snowflake/databases/{}/{}/schema.sql", database_name, name))
            }
            SnowflakeResourceAddress::Table(database_name, schema_name, name) => PathBuf::from(format!(
                "snowflake/databases/{}/{}/{}/table.sql",
                database_name, schema_name, name
            )),
            SnowflakeResourceAddress::User(name) => PathBuf::from(format!("snowflake/users/{}.ron", name)),
            SnowflakeResourceAddress::Role(name) => PathBuf::from(format!("snowflake/roles/{}.ron", name)),
        }
    }

    fn from_path(path: &Path) -> Result<Self, anyhow::Error> {
        let path_components: Vec<&str> = path
            .components()
            .into_iter()
            .map(|s| s.as_os_str().to_str().unwrap())
            .collect();

        match path_components[..] {
            ["snowflake", "warehouses", name] if name.ends_with(".sql") => {
                Ok(SnowflakeResourceAddress::Warehouse(strip_sql_suffix(name)))
            }
            ["snowflake", "databases", name, "database.sql"] => Ok(SnowflakeResourceAddress::Database(name.to_string())),
            ["snowflake", "databases", database_name, name, "schema.sql"] => {
                Ok(SnowflakeResourceAddress::Schema(database_name.to_string(), name.to_string()))
            }
            ["snowflake", "databases", database_name, schema_name, name, "table.sql"] => Ok(SnowflakeResourceAddress::Table(
                database_name.to_string(),
                schema_name.to_string(),
                name.to_string(),
            )),
            ["snowflake", "users", name] if name.ends_with(".ron") => {
                Ok(SnowflakeResourceAddress::User(strip_ron_suffix(name)))
            }
            ["snowflake", "roles", name] if name.ends_with(".ron") => {
                Ok(SnowflakeResourceAddress::Role(strip_ron_suffix(name)))
            }
            _ => Err(invalid_addr_path(path)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SQLDefinition {
    statement: String,
}

impl Resource for SQLDefinition {
    fn to_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        Ok(self.statement.clone().into_bytes())
    }

    fn from_bytes(_addr: &impl ResourceAddress, s: &[u8]) -> Result<Self, anyhow::Error>
    where
        Self: Sized,
    {
        let statement = str::from_utf8(s)?;

        Ok(SQLDefinition {
            statement: statement.into(),
        })
    }
}

/// Snowflake User resource - represents a user in Snowflake's RBAC system.
/// Properties map to Snowflake's ALTER USER / CREATE USER parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SnowflakeUser {
    /// The login name for the user (can differ from the user name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_name: Option<String>,
    /// Display name for the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// First name of the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    /// Last name of the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// Email address for the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Default warehouse for the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_warehouse: Option<String>,
    /// Default namespace (database or database.schema) for the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_namespace: Option<String>,
    /// Default role for the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_role: Option<String>,
    /// Default secondary roles (ALL or NONE).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_secondary_roles: Option<String>,
    /// Whether the user is disabled.
    #[serde(default)]
    pub disabled: bool,
    /// RSA public key for key-pair authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsa_public_key: Option<String>,
    /// Secondary RSA public key for key rotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsa_public_key_2: Option<String>,
    /// Comment/description for the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Roles granted to this user.
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub granted_roles: HashSet<String>,
}

impl Resource for SnowflakeUser {
    fn to_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        let pretty_config = PrettyConfig::default().struct_names(true);
        match RON.to_string_pretty(&self, pretty_config) {
            Ok(s) => Ok(s.into()),
            Err(e) => Err(e.into()),
        }
    }

    fn from_bytes(_addr: &impl ResourceAddress, s: &[u8]) -> Result<Self, anyhow::Error>
    where
        Self: Sized,
    {
        let s = str::from_utf8(s)?;
        Ok(RON.from_str(s)?)
    }
}

/// Snowflake Role resource - represents a role in Snowflake's RBAC system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SnowflakeRole {
    /// Comment/description for the role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Roles granted to this role (i.e., roles this role inherits privileges from).
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub granted_roles: HashSet<String>,
}

impl Resource for SnowflakeRole {
    fn to_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        let pretty_config = PrettyConfig::default().struct_names(true);
        match RON.to_string_pretty(&self, pretty_config) {
            Ok(s) => Ok(s.into()),
            Err(e) => Err(e.into()),
        }
    }

    fn from_bytes(_addr: &impl ResourceAddress, s: &[u8]) -> Result<Self, anyhow::Error>
    where
        Self: Sized,
    {
        let s = str::from_utf8(s)?;
        Ok(RON.from_str(s)?)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SnowflakeConnectorOp {
    Execute(SQLDefinition),
    Delete,
    // User operations
    CreateUser(SnowflakeUser),
    AlterUser(SnowflakeUser, SnowflakeUser), // (old, new)
    DropUser,
    // Role operations
    CreateRole(SnowflakeRole),
    AlterRole(SnowflakeRole, SnowflakeRole), // (old, new)
    DropRole,
    // Role grant operations - explicit ops for granting/revoking roles
    GrantRoleToUser(String),    // role_name to grant to user at addr
    RevokeRoleFromUser(String), // role_name to revoke from user at addr
    GrantRoleToRole(String),    // role_name to grant to role at addr
    RevokeRoleFromRole(String), // role_name to revoke from role at addr
}

impl ConnectorOp for SnowflakeConnectorOp {
    fn to_string(&self) -> Result<String, anyhow::Error> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn from_str(s: &str) -> Result<Self, anyhow::Error>
    where
        Self: Sized,
    {
        Ok(serde_json::from_str(s)?)
    }
}

impl SnowflakeConnector {
    async fn get_ddl(&self, object_type: &str, name: &str) -> Result<Option<String>, anyhow::Error> {
        let api = self.get_api(None, None).await?;
        let res = api.exec(&format!("SELECT GET_DDL('{}', '{}');", object_type, name)).await?;

        match res {
            snowflake_api::QueryResult::Arrow(arrow) => {
                tracing::warn!("SELECT GET DDL: arrow {:?}", arrow);
                let ddl = arrow.first().unwrap().column(0);
                let ddl: StringArray = ddl.to_data().into();
                let ddl = ddl.value(0);

                // DDLs returned from GET DDL are recursive, so
                // we'll just crudely pick out the first statement...

                let mut ddl: Vec<&str> = ddl.split(";").take(1).collect();
                let mut first_statement = ddl.remove(0).to_string();
                first_statement.push_str(";\n");

                return Ok(Some(first_statement));
            }
            snowflake_api::QueryResult::Empty => {
                tracing::warn!("SELECT GET DDL: EMPTY????");
            }
            snowflake_api::QueryResult::Json(json) => {
                tracing::warn!("SELECT GET DDL: json {}", json.value);
            }
        }

        Ok(Some(String::from("SELECT 1;")))
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

        for warehouse_name in SnowflakeConnector::list_warehouses(&api).await? {
            results.push(SnowflakeResourceAddress::Warehouse(warehouse_name).to_path_buf());
        }

        for database_name in &SnowflakeConnector::list_databases(&api).await? {
            if database_name == "SNOWFLAKE" {
                continue;
            }

            results.push(SnowflakeResourceAddress::Database(database_name.clone()).to_path_buf());

            for schema_name in &SnowflakeConnector::list_schemas(&api, &database_name).await? {
                results.push(SnowflakeResourceAddress::Schema(database_name.clone(), schema_name.clone()).to_path_buf());
                for table_name in &SnowflakeConnector::list_tables(&api, &database_name, &schema_name).await? {
                    results.push(
                        SnowflakeResourceAddress::Table(database_name.clone(), schema_name.clone(), table_name.clone())
                            .to_path_buf(),
                    );
                }
            }
        }

        // List users
        for user_name in SnowflakeConnector::list_users(&api).await? {
            results.push(SnowflakeResourceAddress::User(user_name).to_path_buf());
        }

        // List roles
        for role_name in SnowflakeConnector::list_roles(&api).await? {
            results.push(SnowflakeResourceAddress::Role(role_name).to_path_buf());
        }

        Ok(results)
    }

    async fn get(&self, addr: &Path) -> Result<Option<GetResourceResponse>, anyhow::Error> {
        let addr = SnowflakeResourceAddress::from_path(addr)?;
        match &addr {
            addr => match &addr {
                SnowflakeResourceAddress::Warehouse(name) => {
                    let ddl = self.get_ddl("WAREHOUSE", &name).await?;
                    if let Some(ddl) = ddl {
                        get_resource_response!(SQLDefinition::from_bytes(addr, &ddl.as_bytes())?)
                    } else {
                        Ok(None)
                    }
                }
                SnowflakeResourceAddress::Database(name) => {
                    let ddl = self.get_ddl("DATABASE", &name).await?;
                    if let Some(ddl) = ddl {
                        get_resource_response!(SQLDefinition::from_bytes(addr, &ddl.as_bytes())?)
                    } else {
                        Ok(None)
                    }
                }
                SnowflakeResourceAddress::Schema(database_name, name) => {
                    let ddl = self.get_ddl("SCHEMA", &format!("{}.{}", database_name, name)).await?;
                    if let Some(ddl) = ddl {
                        get_resource_response!(SQLDefinition::from_bytes(addr, &ddl.as_bytes())?)
                    } else {
                        Ok(None)
                    }
                }
                SnowflakeResourceAddress::Table(database_name, schema_name, name) => {
                    let ddl = self
                        .get_ddl("TABLE", &format!("{}.{}.{}", database_name, schema_name, name))
                        .await?;
                    if let Some(ddl) = ddl {
                        get_resource_response!(SQLDefinition::from_bytes(addr, &ddl.as_bytes())?)
                    } else {
                        Ok(None)
                    }
                }
                SnowflakeResourceAddress::User(name) => {
                    if let Some(user) = self.get_user(name).await? {
                        get_resource_response!(user)
                    } else {
                        Ok(None)
                    }
                }
                SnowflakeResourceAddress::Role(name) => {
                    if let Some(role) = self.get_role(name).await? {
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
            SnowflakeResourceAddress::Database(_name) => match (current, desired) {
                (None, None) => Ok(Vec::new()),
                (Some(_), None) => Ok(Vec::new()),
                (Some(_), Some(_)) => Ok(Vec::new()),
                (None, Some(definition)) => {
                    let _definition = SQLDefinition::from_bytes(&addr, &definition);
                    let _api = self.get_api(None, None).await?;
                    Ok(vec![])
                }
            },
            SnowflakeResourceAddress::User(name) => {
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
                            granted_roles: HashSet::new(),
                            ..old_user.clone()
                        };
                        let new_props = SnowflakeUser {
                            granted_roles: HashSet::new(),
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
            SnowflakeResourceAddress::Role(name) => {
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
            SnowflakeResourceAddress::Warehouse(name) => {
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
            SnowflakeResourceAddress::Database(name) => {
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
            SnowflakeResourceAddress::Schema(database_name, name) => {
                let api = self.get_api(Some(&database_name), None).await?;
                match &op {
                    SnowflakeConnectorOp::Execute(def) => {
                        let _res = api.exec(&def.statement.to_string()).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", def.statement)),
                        })
                    }
                    SnowflakeConnectorOp::Delete => {
                        let statement = format!("DROP SCHEMA {}.{};", database_name, name);
                        let _res = api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", statement)),
                        })
                    }
                    _ => bail!("Invalid operation for Schema address"),
                }
            }
            SnowflakeResourceAddress::Table(database_name, schema_name, name) => {
                let api = self.get_api(Some(&database_name), Some(&schema_name)).await?;
                match &op {
                    SnowflakeConnectorOp::Execute(def) => {
                        let _res = api.exec(&def.statement.to_string()).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", def.statement)),
                        })
                    }
                    SnowflakeConnectorOp::Delete => {
                        let statement = format!("DROP TABLE {}.{}.{};", database_name, schema_name, name);
                        let _res = api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", statement)),
                        })
                    }
                    _ => bail!("Invalid operation for Table address"),
                }
            }
            SnowflakeResourceAddress::User(name) => {
                let api = self.get_api(None, None).await?;
                match op {
                    SnowflakeConnectorOp::CreateUser(user) => {
                        let statement = Self::build_create_user_sql(&name, &user);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Created Snowflake user `{}`", name)),
                        })
                    }
                    SnowflakeConnectorOp::AlterUser(_old_user, new_user) => {
                        let statement = Self::build_alter_user_sql(&name, &new_user);
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
            SnowflakeResourceAddress::Role(name) => {
                let api = self.get_api(None, None).await?;
                match op {
                    SnowflakeConnectorOp::CreateRole(role) => {
                        // Create the role (grants are handled as separate ops)
                        let statement = Self::build_create_role_sql(&name, &role);
                        api.exec(&statement).await?;

                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Created Snowflake role `{}`", name)),
                        })
                    }
                    SnowflakeConnectorOp::AlterRole(_old_role, new_role) => {
                        // Update comment (grants are handled as separate ops)
                        let statement = Self::build_alter_role_sql(&name, &new_role);
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

    async fn eq(&self, _addr: &Path, a: &[u8], b: &[u8]) -> anyhow::Result<bool> {
        Ok(a == b)
    }

    async fn diag(&self, addr: &Path, a: &[u8]) -> Result<Option<DiagnosticResponse>, anyhow::Error> {
        let parsed_addr = SnowflakeResourceAddress::from_path(addr)?;

        match parsed_addr {
            // RON-based resources (users, roles)
            SnowflakeResourceAddress::User(_) => ron_check_syntax::<SnowflakeUser>(a),
            SnowflakeResourceAddress::Role(_) => ron_check_syntax::<SnowflakeRole>(a),
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

impl SnowflakeConnector {
    pub async fn get_api(&self, database: Option<&str>, schema: Option<&str>) -> Result<Arc<SnowflakeApi>, anyhow::Error> {
        if let Some(api) = &*self.api.lock().await {
            return Ok(api.clone());
        }

        let Some(ref config) = *self.config.lock().await else {
            bail!("SnowflakeConnector: Uninitialized!");
        };

        let new_api = Arc::new(SnowflakeApi::with_certificate_auth(
            &config.account,
            Some(&config.warehouse),
            database,
            schema,
            &config.user,
            Some(&config.role),
            &config.private_key,
        )?);

        *self.api.lock().await = Some(new_api.clone());

        Ok(new_api)
    }

    //Execute `EXPLAIN (statement)``;
    pub async fn execute_explain(api: &SnowflakeApi, statement: &Statement) -> Result<serde_json::Value, anyhow::Error> {
        let statement = match statement {
            Statement::Explain { .. } => statement,
            _ => &Statement::Explain {
                estimate: false,
                query_plan: false,
                options: None,
                describe_alias: DescribeAlias::Explain,
                analyze: false,
                verbose: false,
                statement: Box::new(statement.clone()),
                format: None,
            },
        };

        let res = api.exec(&statement.to_string()).await?;
        match res {
            snowflake_api::QueryResult::Arrow(_) => {
                bail!(SnowflakeConnectorError::UnexpectedArrowResult)
            }
            snowflake_api::QueryResult::Empty => {
                bail!(SnowflakeConnectorError::UnexpectedEmptyResult)
            }
            snowflake_api::QueryResult::Json(json) => Ok(json.value),
        }
    }

    pub async fn execute_statement(api: &SnowflakeApi, statement: &Statement) -> Result<serde_json::Value, anyhow::Error> {
        let res = api.exec(&statement.to_string()).await?;
        match res {
            snowflake_api::QueryResult::Arrow(_) => {
                bail!(SnowflakeConnectorError::UnexpectedArrowResult)
            }
            snowflake_api::QueryResult::Empty => {
                bail!(SnowflakeConnectorError::UnexpectedEmptyResult)
            }
            snowflake_api::QueryResult::Json(json) => Ok(json.value),
        }
    }

    pub async fn list_warehouses(api: &SnowflakeApi) -> Result<Vec<String>, anyhow::Error> {
        let res = api.exec("SHOW WAREHOUSES;").await?;
        let mut warehouses = Vec::new();
        if let QueryResult::Json(json_result) = res {
            tracing::warn!("SHOW WAREHOUSES: {}", json_result.value);
            for row in json_result.value.as_array().unwrap() {
                warehouses.push(row.as_array().unwrap()[0].as_str().unwrap().to_string());
            }
        }

        Ok(warehouses)
    }

    pub async fn list_databases(api: &SnowflakeApi) -> Result<Vec<String>, anyhow::Error> {
        let res = api.exec("SHOW DATABASES;").await?;
        let mut databases = Vec::new();
        if let QueryResult::Json(json_result) = res {
            tracing::debug!("SHOW DATABASES: {}", json_result.value);
            // TODO remove these unwraps!
            for row in json_result.value.as_array().unwrap() {
                // Good lord. So this rust snowflake crate only gives results
                // as arrays of arrays... Meaning there's no method to this madness.
                // This is truly awful and motivating enough to
                // switch to the other snowflake rust crate
                let row = row.as_array().unwrap();
                let kind = row[9].as_str().unwrap();
                let name = row[1].as_str().unwrap();
                if kind == "STANDARD" {
                    databases.push(name.to_string());
                }
            }
        }

        Ok(databases)
    }

    pub async fn list_schemas(api: &SnowflakeApi, database_name: &str) -> Result<Vec<String>, anyhow::Error> {
        let res = api.exec(&format!("SHOW SCHEMAS IN DATABASE {};", database_name)).await?;
        let mut schemas = Vec::new();
        if let QueryResult::Json(json_result) = res {
            tracing::debug!("SHOW SCHEMAS: {}", json_result.value);
            for row in json_result.value.as_array().unwrap() {
                schemas.push(row.as_array().unwrap()[1].as_str().unwrap().to_string());
            }
        }

        Ok(schemas)
    }

    pub async fn list_tables(api: &SnowflakeApi, database_name: &str, schema_name: &str) -> Result<Vec<String>, anyhow::Error> {
        let res = api
            .exec(&format!("SHOW TABLES IN SCHEMA {}.{};", database_name, schema_name))
            .await?;
        let mut tables = Vec::new();
        if let QueryResult::Json(json_result) = res {
            tracing::debug!("SHOW TABLES: {}", json_result.value);
            for row in json_result.value.as_array().unwrap() {
                tables.push(row.as_array().unwrap()[1].as_str().unwrap().to_string());
            }
        }

        Ok(tables)
    }

    pub async fn list_users(api: &SnowflakeApi) -> Result<Vec<String>, anyhow::Error> {
        let res = api.exec("SHOW USERS;").await?;
        let mut users = Vec::new();
        if let QueryResult::Json(json_result) = res {
            tracing::debug!("SHOW USERS: {}", json_result.value);
            for row in json_result.value.as_array().unwrap() {
                // SHOW USERS returns: name, created_on, login_name, display_name, ...
                users.push(row.as_array().unwrap()[0].as_str().unwrap().to_string());
            }
        }
        Ok(users)
    }

    /// Get user properties using DESCRIBE USER command.
    /// Returns None if user doesn't exist.
    pub async fn get_user(&self, name: &str) -> Result<Option<SnowflakeUser>, anyhow::Error> {
        let api = self.get_api(None, None).await?;
        let res = api.exec(&format!("DESCRIBE USER \"{}\";", name)).await;

        match res {
            Ok(QueryResult::Json(json_result)) => {
                tracing::debug!("DESCRIBE USER {}: \"{}\"", name, json_result.value);

                // DESCRIBE USER returns rows like: property, value, default, description
                // We need to parse these into our SnowflakeUser struct
                let mut user = SnowflakeUser {
                    login_name: None,
                    display_name: None,
                    first_name: None,
                    last_name: None,
                    email: None,
                    default_warehouse: None,
                    default_namespace: None,
                    default_role: None,
                    default_secondary_roles: None,
                    disabled: false,
                    rsa_public_key: None,
                    rsa_public_key_2: None,
                    comment: None,
                    granted_roles: HashSet::new(),
                };

                for row in json_result.value.as_array().unwrap_or(&vec![]) {
                    let row = row.as_array().unwrap();
                    let property = row[0].as_str().unwrap_or("");
                    let value = row[1].as_str().unwrap_or("");

                    // Skip if value is empty or "null"
                    let value_opt = if value.is_empty() || value == "null" {
                        None
                    } else {
                        Some(value.to_string())
                    };

                    match property {
                        "LOGIN_NAME" => user.login_name = value_opt,
                        "DISPLAY_NAME" => user.display_name = value_opt,
                        "FIRST_NAME" => user.first_name = value_opt,
                        "LAST_NAME" => user.last_name = value_opt,
                        "EMAIL" => user.email = value_opt,
                        "DEFAULT_WAREHOUSE" => user.default_warehouse = value_opt,
                        "DEFAULT_NAMESPACE" => user.default_namespace = value_opt,
                        "DEFAULT_ROLE" => user.default_role = value_opt,
                        "DEFAULT_SECONDARY_ROLES" => user.default_secondary_roles = value_opt,
                        "DISABLED" => user.disabled = value == "true",
                        "RSA_PUBLIC_KEY" => user.rsa_public_key = value_opt,
                        "RSA_PUBLIC_KEY_2" => user.rsa_public_key_2 = value_opt,
                        "COMMENT" => user.comment = value_opt,
                        _ => {}
                    }
                }

                // Fetch roles granted to this user
                user.granted_roles = Self::get_user_granted_roles(&api, name).await?;
                Ok(Some(user))
            }
            Ok(QueryResult::Arrow(arrow)) => {
                tracing::debug!("DESCRIBE USER {} returned Arrow: {:?}", name, arrow);
                // Parse Arrow format similar to JSON
                if arrow.is_empty() {
                    return Ok(None);
                }

                let mut user = SnowflakeUser {
                    login_name: None,
                    display_name: None,
                    first_name: None,
                    last_name: None,
                    email: None,
                    default_warehouse: None,
                    default_namespace: None,
                    default_role: None,
                    default_secondary_roles: None,
                    disabled: false,
                    rsa_public_key: None,
                    rsa_public_key_2: None,
                    comment: None,
                    granted_roles: HashSet::new(),
                };

                for batch in &arrow {
                    let property_col: StringArray = batch.column(0).to_data().into();
                    let value_col: StringArray = batch.column(1).to_data().into();

                    for i in 0..batch.num_rows() {
                        let property = property_col.value(i);
                        let value = value_col.value(i);

                        let value_opt = if value.is_empty() || value == "null" {
                            None
                        } else {
                            Some(value.to_string())
                        };

                        match property {
                            "LOGIN_NAME" => user.login_name = value_opt,
                            "DISPLAY_NAME" => user.display_name = value_opt,
                            "FIRST_NAME" => user.first_name = value_opt,
                            "LAST_NAME" => user.last_name = value_opt,
                            "EMAIL" => user.email = value_opt,
                            "DEFAULT_WAREHOUSE" => user.default_warehouse = value_opt,
                            "DEFAULT_NAMESPACE" => user.default_namespace = value_opt,
                            "DEFAULT_ROLE" => user.default_role = value_opt,
                            "DEFAULT_SECONDARY_ROLES" => user.default_secondary_roles = value_opt,
                            "DISABLED" => user.disabled = value == "true",
                            "RSA_PUBLIC_KEY" => user.rsa_public_key = value_opt,
                            "RSA_PUBLIC_KEY_2" => user.rsa_public_key_2 = value_opt,
                            "COMMENT" => user.comment = value_opt,
                            _ => {}
                        }
                    }
                }

                // Fetch roles granted to this user
                user.granted_roles = Self::get_user_granted_roles(&api, name).await?;
                Ok(Some(user))
            }
            Ok(QueryResult::Empty) => Ok(None),
            Err(e) => {
                // Check if it's a "user does not exist" error
                let err_str = e.to_string();
                if err_str.contains("does not exist") || err_str.contains("Object does not exist") {
                    Ok(None)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    /// Build CREATE USER SQL statement from SnowflakeUser
    fn build_create_user_sql(name: &str, user: &SnowflakeUser) -> String {
        let mut sql = format!("CREATE USER \"{}\"", name);
        let mut props = Vec::new();

        if let Some(ref login_name) = user.login_name {
            props.push(format!("LOGIN_NAME = '{}'", login_name));
        }
        if let Some(ref display_name) = user.display_name {
            props.push(format!("DISPLAY_NAME = '{}'", display_name));
        }
        if let Some(ref first_name) = user.first_name {
            props.push(format!("FIRST_NAME = '{}'", first_name));
        }
        if let Some(ref last_name) = user.last_name {
            props.push(format!("LAST_NAME = '{}'", last_name));
        }
        if let Some(ref email) = user.email {
            props.push(format!("EMAIL = '{}'", email));
        }
        if let Some(ref default_warehouse) = user.default_warehouse {
            props.push(format!("DEFAULT_WAREHOUSE = {}", default_warehouse));
        }
        if let Some(ref default_namespace) = user.default_namespace {
            props.push(format!("DEFAULT_NAMESPACE = {}", default_namespace));
        }
        if let Some(ref default_role) = user.default_role {
            props.push(format!("DEFAULT_ROLE = {}", default_role));
        }
        if let Some(ref default_secondary_roles) = user.default_secondary_roles {
            // DEFAULT_SECONDARY_ROLES can be 'ALL' or 'NONE', or a specific list
            if default_secondary_roles == "ALL" || default_secondary_roles == "NONE" {
                props.push(format!("DEFAULT_SECONDARY_ROLES = ('{}')", default_secondary_roles));
            } else {
                props.push(format!("DEFAULT_SECONDARY_ROLES = ({})", default_secondary_roles));
            }
        }
        if user.disabled {
            props.push("DISABLED = TRUE".to_string());
        }
        if let Some(ref rsa_public_key) = user.rsa_public_key {
            props.push(format!("RSA_PUBLIC_KEY = '{}'", rsa_public_key));
        }
        if let Some(ref rsa_public_key_2) = user.rsa_public_key_2 {
            props.push(format!("RSA_PUBLIC_KEY_2 = '{}'", rsa_public_key_2));
        }
        if let Some(ref comment) = user.comment {
            props.push(format!("COMMENT = '{}'", comment.replace('\'', "''")));
        }

        if !props.is_empty() {
            sql.push(' ');
            sql.push_str(&props.join(" "));
        }

        sql.push(';');
        sql
    }

    /// Build ALTER USER SQL statement from SnowflakeUser (sets all properties)
    fn build_alter_user_sql(name: &str, user: &SnowflakeUser) -> String {
        let mut sql = format!("ALTER USER \"{}\" SET", name);
        let mut props = Vec::new();

        // For ALTER USER, we need to set all properties to their desired values
        if let Some(ref login_name) = user.login_name {
            props.push(format!("LOGIN_NAME = '{}'", login_name));
        }
        if let Some(ref display_name) = user.display_name {
            props.push(format!("DISPLAY_NAME = '{}'", display_name));
        }
        if let Some(ref first_name) = user.first_name {
            props.push(format!("FIRST_NAME = '{}'", first_name));
        }
        if let Some(ref last_name) = user.last_name {
            props.push(format!("LAST_NAME = '{}'", last_name));
        }
        if let Some(ref email) = user.email {
            props.push(format!("EMAIL = '{}'", email));
        }
        if let Some(ref default_warehouse) = user.default_warehouse {
            props.push(format!("DEFAULT_WAREHOUSE = {}", default_warehouse));
        }
        if let Some(ref default_namespace) = user.default_namespace {
            props.push(format!("DEFAULT_NAMESPACE = {}", default_namespace));
        }
        if let Some(ref default_role) = user.default_role {
            props.push(format!("DEFAULT_ROLE = {}", default_role));
        }
        if let Some(ref default_secondary_roles) = user.default_secondary_roles {
            if default_secondary_roles == "ALL" || default_secondary_roles == "NONE" {
                props.push(format!("DEFAULT_SECONDARY_ROLES = ('{}')", default_secondary_roles));
            } else {
                props.push(format!("DEFAULT_SECONDARY_ROLES = ({})", default_secondary_roles));
            }
        }
        props.push(format!("DISABLED = {}", if user.disabled { "TRUE" } else { "FALSE" }));
        if let Some(ref rsa_public_key) = user.rsa_public_key {
            props.push(format!("RSA_PUBLIC_KEY = '{}'", rsa_public_key));
        }
        if let Some(ref rsa_public_key_2) = user.rsa_public_key_2 {
            props.push(format!("RSA_PUBLIC_KEY_2 = '{}'", rsa_public_key_2));
        }
        if let Some(ref comment) = user.comment {
            props.push(format!("COMMENT = '{}'", comment.replace('\'', "''")));
        }

        if props.is_empty() {
            // If no properties to set, return a no-op query
            return format!("SELECT 1; -- No changes for user {}", name);
        }

        sql.push(' ');
        sql.push_str(&props.join(" "));
        sql.push(';');
        sql
    }

    pub async fn list_roles(api: &SnowflakeApi) -> Result<Vec<String>, anyhow::Error> {
        let res = api.exec("SHOW ROLES;").await?;
        let mut roles = Vec::new();
        match res {
            QueryResult::Json(json_result) => {
                tracing::debug!("SHOW ROLES: {}", json_result.value);
                for row in json_result.value.as_array().unwrap_or(&vec![]) {
                    // SHOW ROLES returns: created_on, name, is_default, is_current, is_inherited, ...
                    if let Some(name) = row.as_array().and_then(|r| r.get(1)).and_then(|v| v.as_str()) {
                        roles.push(name.to_string());
                    }
                }
            }
            QueryResult::Arrow(arrow) => {
                for batch in &arrow {
                    if batch.num_columns() > 1 {
                        let name_col: StringArray = batch.column(1).to_data().into();
                        for i in 0..batch.num_rows() {
                            roles.push(name_col.value(i).to_string());
                        }
                    }
                }
            }
            QueryResult::Empty => {}
        }
        Ok(roles)
    }

    /// Get role properties and grants using SHOW ROLES and SHOW GRANTS.
    /// Returns None if role doesn't exist.
    pub async fn get_role(&self, name: &str) -> Result<Option<SnowflakeRole>, anyhow::Error> {
        let api = self.get_api(None, None).await?;

        // First check if role exists using SHOW ROLES LIKE
        let res = api.exec(&format!("SHOW ROLES LIKE '{}';", name)).await;

        let (comment, role_exists) = match res {
            Ok(QueryResult::Json(json_result)) => {
                if let Some(rows) = json_result.value.as_array() {
                    if rows.is_empty() {
                        return Ok(None);
                    }
                    // SHOW ROLES returns: created_on, name, is_default, is_current, is_inherited, assigned_to_users, granted_to_roles, granted_roles, owner, comment
                    let comment = rows
                        .first()
                        .and_then(|r| r.as_array())
                        .and_then(|r| r.get(9))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string());
                    (comment, true)
                } else {
                    return Ok(None);
                }
            }
            Ok(QueryResult::Arrow(arrow)) => {
                if arrow.is_empty() || arrow.first().map(|b| b.num_rows()).unwrap_or(0) == 0 {
                    return Ok(None);
                }
                let comment = if let Some(batch) = arrow.first() {
                    if batch.num_columns() > 9 {
                        let comment_col: StringArray = batch.column(9).to_data().into();
                        let val = comment_col.value(0);
                        if val.is_empty() { None } else { Some(val.to_string()) }
                    } else {
                        None
                    }
                } else {
                    None
                };
                (comment, true)
            }
            Ok(QueryResult::Empty) => return Ok(None),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("does not exist") {
                    return Ok(None);
                }
                return Err(e.into());
            }
        };

        if !role_exists {
            return Ok(None);
        }

        // Get roles granted to this role using SHOW GRANTS TO ROLE
        let mut granted_roles = HashSet::new();
        let grants_res = api.exec(&format!("SHOW GRANTS TO ROLE \"{}\";", name)).await;

        match grants_res {
            Ok(QueryResult::Json(json_result)) => {
                for row in json_result.value.as_array().unwrap_or(&vec![]) {
                    if let Some(row_arr) = row.as_array() {
                        // SHOW GRANTS TO ROLE returns: created_on, privilege, granted_on, name, granted_to, grantee_name, grant_option, granted_by
                        // We're looking for rows where privilege is "USAGE" and granted_on is "ROLE"
                        let privilege = row_arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
                        let granted_on = row_arr.get(2).and_then(|v| v.as_str()).unwrap_or("");
                        let role_name = row_arr.get(3).and_then(|v| v.as_str()).unwrap_or("");

                        if privilege == "USAGE" && granted_on == "ROLE" && !role_name.is_empty() {
                            granted_roles.insert(role_name.to_string());
                        }
                    }
                }
            }
            Ok(QueryResult::Arrow(arrow)) => {
                for batch in &arrow {
                    if batch.num_columns() >= 4 {
                        let privilege_col: StringArray = batch.column(1).to_data().into();
                        let granted_on_col: StringArray = batch.column(2).to_data().into();
                        let name_col: StringArray = batch.column(3).to_data().into();

                        for i in 0..batch.num_rows() {
                            let privilege = privilege_col.value(i);
                            let granted_on = granted_on_col.value(i);
                            let role_name = name_col.value(i);

                            if privilege == "USAGE" && granted_on == "ROLE" && !role_name.is_empty() {
                                granted_roles.insert(role_name.to_string());
                            }
                        }
                    }
                }
            }
            Ok(QueryResult::Empty) => {}
            Err(_) => {} // Ignore errors fetching grants, role still exists
        }

        Ok(Some(SnowflakeRole { comment, granted_roles }))
    }

    /// Build CREATE ROLE SQL statement
    fn build_create_role_sql(name: &str, role: &SnowflakeRole) -> String {
        let mut sql = format!("CREATE ROLE \"{}\"", name);

        if let Some(ref comment) = role.comment {
            sql.push_str(&format!(" COMMENT = '{}'", comment.replace('\'', "''")));
        }

        sql.push(';');
        sql
    }

    /// Build ALTER ROLE SQL statement for comment changes
    fn build_alter_role_sql(name: &str, role: &SnowflakeRole) -> String {
        if let Some(ref comment) = role.comment {
            format!("ALTER ROLE \"{}\" SET COMMENT = '{}';", name, comment.replace('\'', "''"))
        } else {
            format!("ALTER ROLE \"{}\" UNSET COMMENT;", name)
        }
    }

    /// Get roles granted to a user
    async fn get_user_granted_roles(api: &SnowflakeApi, user_name: &str) -> Result<HashSet<String>, anyhow::Error> {
        let mut granted_roles = HashSet::new();
        let grants_res = api.exec(&format!("SHOW GRANTS TO USER \"{}\";", user_name)).await;

        match grants_res {
            Ok(QueryResult::Json(json_result)) => {
                for row in json_result.value.as_array().unwrap_or(&vec![]) {
                    if let Some(row_arr) = row.as_array() {
                        // SHOW GRANTS TO USER returns: created_on, role, granted_to, grantee_name, granted_by
                        // The role name is in position 1
                        if let Some(role_name) = row_arr.get(1).and_then(|v| v.as_str()) {
                            if !role_name.is_empty() {
                                granted_roles.insert(role_name.to_string());
                            }
                        }
                    }
                }
            }
            Ok(QueryResult::Arrow(arrow)) => {
                for batch in &arrow {
                    if batch.num_columns() >= 2 {
                        let role_col: StringArray = batch.column(1).to_data().into();
                        for i in 0..batch.num_rows() {
                            let role_name = role_col.value(i);
                            if !role_name.is_empty() {
                                granted_roles.insert(role_name.to_string());
                            }
                        }
                    }
                }
            }
            Ok(QueryResult::Empty) => {}
            Err(_) => {} // Ignore errors fetching grants, user still exists
        }

        Ok(granted_roles)
    }
}
