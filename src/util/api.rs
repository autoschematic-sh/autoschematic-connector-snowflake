use std::sync::Arc;

use anyhow::bail;
use arrow::array::StringArray;
use autoschematic_core::connector::GetResourceResponse;
use indexmap::IndexSet;
use snowflake_api::{JsonResult, QueryResult, SnowflakeApi};
use sqlparser::ast::{DescribeAlias, Statement};

use crate::{
    connector::SnowflakeConnector,
    error::SnowflakeConnectorError,
    resource::{SnowflakeRole, SnowflakeUser},
    util::record::JsonResultExt,
};

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

    pub async fn get_ddl(&self, object_type: &str, name: &str) -> Result<Option<GetResourceResponse>, anyhow::Error> {
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

                return Ok(Some(GetResourceResponse {
                    resource_definition: first_statement.into_bytes(),
                    outputs: None,
                }));
            }
            snowflake_api::QueryResult::Empty => {
                tracing::warn!("SELECT GET DDL: EMPTY????");
            }
            snowflake_api::QueryResult::Json(json) => {
                tracing::warn!("SELECT GET DDL: json {}", json.value);
            }
        }

        // if let Some(ddl) = ddl {
        // } else {
        //     Ok(None)
        // }

        Ok(None)
    }

    /// Wraps a statement in EXPLAIN {statement};
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

    pub async fn execute_ddl_statement(api: &SnowflakeApi, statement: &Statement) -> Result<serde_json::Value, anyhow::Error> {
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

    pub async fn describe_if_exists(api: &SnowflakeApi, query: &str) -> Result<Option<JsonResult>, anyhow::Error> {
        match api.exec(query).await {
            Ok(QueryResult::Json(json_result)) => Ok(Some(json_result)),
            Ok(snowflake_api::QueryResult::Arrow(_)) => {
                bail!(SnowflakeConnectorError::UnexpectedArrowResult)
            }
            Ok(snowflake_api::QueryResult::Empty) => {
                return Ok(None);
            }
            Err(e) => {
                let err_str = e.to_string();
                tracing::debug!("describe_if_exists: e: {err_str}");
                if err_str.contains("does not exist") {
                    return Ok(None);
                }
                return Err(e.into());
            }
        }
    }

    pub async fn list_warehouses(api: &SnowflakeApi) -> Result<Vec<String>, anyhow::Error> {
        let res = api.exec("SHOW WAREHOUSES;").await?;
        let mut warehouses = Vec::new();
        if let QueryResult::Json(json_result) = res {
            tracing::warn!("SHOW WAREHOUSES: {}", json_result.value);
            for row in json_result.iter_records()? {
                let row = row?;
                let name: String = row.require_as("name")?;
                warehouses.push(name);
            }
        }

        Ok(warehouses)
    }

    pub async fn list_databases(api: &SnowflakeApi) -> Result<Vec<String>, anyhow::Error> {
        let res = api.exec("SHOW DATABASES;").await?;
        let mut databases = Vec::new();
        if let QueryResult::Json(json_result) = res {
            tracing::debug!("SHOW DATABASES: {}", json_result.value);
            for row in json_result.iter_records()? {
                let row = row?;
                let kind: String = row.require_as("kind")?;
                let name: String = row.require_as("name")?;
                if kind == "STANDARD" {
                    databases.push(name);
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
            for row in json_result.iter_records()? {
                let row = row?;
                let name: String = row.require_as("name")?;
                schemas.push(name);
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
            tracing::warn!("SHOW TABLES: {}", json_result.value);
            for row in json_result.iter_records()? {
                let row = row?;
                let name: String = row.require_as("name")?;
                tables.push(name);
            }
        }

        Ok(tables)
    }

    pub async fn list_users(api: &SnowflakeApi) -> Result<Vec<String>, anyhow::Error> {
        let res = api.exec("SHOW USERS;").await?;
        let mut users = Vec::new();
        if let QueryResult::Json(json_result) = res {
            tracing::debug!("SHOW USERS: {}", json_result.value);
            for row in json_result.iter_records()? {
                let row = row?;
                let name: String = row.require_as("name")?;
                users.push(name);
            }
        }
        Ok(users)
    }

    pub async fn get_user(api: &SnowflakeApi, name: &str) -> Result<Option<SnowflakeUser>, anyhow::Error> {
        // TODO We need to match e (error) as like, "%does not exist%"...
        let Some(json_result) = SnowflakeConnector::describe_if_exists(api, &format!("DESCRIBE USER \"{}\";", name)).await?
        else {
            return Ok(None);
        };
        // tracing::debug!("DESCRIBE USER {}: \"{}\"", name, json_result.value);
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
            granted_roles: IndexSet::new(),
        };

        for row in json_result.iter_records()? {
            let row = row?;
            let property: String = row.require_as("property")?;
            let value: String = row.require_as("value")?;

            // Treat empty or "null" as None
            let value_opt = if value.is_empty() || value == "null" {
                None
            } else {
                Some(value.to_string())
            };

            match property.as_str() {
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
    pub async fn get_role(api: &SnowflakeApi, name: &str) -> Result<Option<SnowflakeRole>, anyhow::Error> {
        // First check if role exists using SHOW ROLES LIKE
        let Some(json_result) = Self::describe_if_exists(api, &format!("SHOW ROLES LIKE '{}';", name)).await? else {
            return Ok(None);
        };

        let mut comment = None;
        let mut owner = None;

        for row in json_result.iter_records()? {
            let row = row?;

            comment = row.get_as("comment")?;
            owner = row.get_as("owner")?.filter(|s: &String| !s.is_empty());
        }

        // Get roles granted to this role via SHOW GRANTS
        let granted_roles = Self::get_role_granted_roles(api, name).await?;

        Ok(Some(SnowflakeRole {
            owner,
            comment,
            granted_roles,
        }))
    }

    /// Get roles granted to a user via SHOW GRANTS TO USER.
    async fn get_user_granted_roles(api: &SnowflakeApi, user_name: &str) -> Result<IndexSet<String>, anyhow::Error> {
        let mut granted_roles = Vec::new();

        // SHOW GRANTS TO USER returns: created_on, role, granted_to, grantee_name, granted_by
        let query = format!("SHOW GRANTS TO USER \"{}\";", user_name);

        if let Ok(QueryResult::Json(json_result)) = api.exec(&query).await {
            for row in json_result.iter_records()? {
                let row = row?;
                let Ok(Some(role_name)): Result<Option<String>, _> = row.get_as("role") else {
                    continue;
                };
                let role_name = role_name.strip_prefix("\"").unwrap_or(&role_name);
                let role_name = role_name.strip_suffix("\"").unwrap_or(&role_name);
                if !role_name.is_empty() {
                    granted_roles.push(role_name.to_string());
                }
            }
        }

        granted_roles.sort();

        Ok(IndexSet::from_iter(granted_roles.into_iter()))
    }

    /// Get roles granted to a role via SHOW GRANTS TO ROLE.
    async fn get_role_granted_roles(api: &SnowflakeApi, role_name: &str) -> Result<IndexSet<String>, anyhow::Error> {
        let mut granted_roles = Vec::new();

        // SHOW GRANTS TO ROLE returns: created_on, privilege, granted_on, name, granted_to, grantee_name, grant_option, granted_by
        // We filter for privilege="USAGE" and granted_on="ROLE" to get role membership grants
        let query = format!("SHOW GRANTS TO ROLE \"{}\";", role_name);

        if let Ok(QueryResult::Json(json_result)) = api.exec(&query).await {
            for row in json_result.iter_records()? {
                let row = row?;
                let privilege: String = row.require_as("privilege")?;
                let granted_on: String = row.require_as("granted_on")?;

                if privilege == "USAGE" && granted_on == "ROLE" {
                    let Some(role_name): Option<String> = row.get_as("name")? else {
                        continue;
                    };
                    let role_name = role_name.strip_prefix("\"").unwrap_or(&role_name);
                    let role_name = role_name.strip_suffix("\"").unwrap_or(&role_name);
                    if !role_name.is_empty() {
                        granted_roles.push(role_name.to_string());
                    }
                }
            }
        }

        granted_roles.sort();

        Ok(IndexSet::from_iter(granted_roles.into_iter()))
    }
}
