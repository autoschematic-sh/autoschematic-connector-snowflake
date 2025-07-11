use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Error, bail};
use arrow::array::StringArray;
use async_trait::async_trait;
use autoschematic_core::{
    connector::{
        Connector, ConnectorOp, ConnectorOutbox, FilterOutput, GetResourceOutput, OpExecOutput, OpPlanOutput, Resource,
        ResourceAddress,
    },
    diag::{Diagnostic, DiagnosticOutput, DiagnosticPosition, DiagnosticSeverity, DiagnosticSpan},
    error::{AutoschematicError, AutoschematicErrorType},
    error_util::invalid_addr_path,
    get_resource_output,
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use snowflake_api::{QueryResult, SnowflakeApi};
use sqlparser::ast::{DescribeAlias, SqlOption, Statement};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Error, Debug)]
enum SnowflakeConnectorError {
    #[error("We were expecting a JSON result, but got Arrow")]
    UnexpectedArrowResult,
    #[error("We were expecting a JSON result, but got an empty one")]
    UnexpectedEmptyResult,
}

pub struct SnowflakeConnector {
    account: String,
    user: String,
    role: String,
    warehouse: String,
    private_key: String,
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
}

fn strip_sql_suffix(s: &str) -> String {
    s.strip_suffix(".sql").unwrap().to_string()
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
                "snowflake/databases/{}/{}/tables/{}.sql",
                database_name, schema_name, name
            )),
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
            ["snowflake", "databases", database_name, schema_name, "tables", name] if name.ends_with(".sql") => Ok(
                SnowflakeResourceAddress::Table(database_name.to_string(), schema_name.to_string(), strip_sql_suffix(name)),
            ),
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

#[derive(Debug, Serialize, Deserialize)]
pub enum SnowflakeConnectorOp {
    Execute(SQLDefinition),
    Delete,
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
    async fn filter(&self, addr: &Path) -> Result<FilterOutput, anyhow::Error> {
        if let Ok(_addr) = SnowflakeResourceAddress::from_path(addr) {
            Ok(FilterOutput::Resource)
        } else {
            Ok(FilterOutput::None)
        }
    }

    async fn new(_name: &str, prefix: &Path, outbox: ConnectorOutbox) -> Result<Arc<dyn Connector>, anyhow::Error>
    where
        Self: Sized,
    {
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
                let private_key = BASE64_STANDARD.decode(private_key_base64).unwrap();

                Ok(String::from_utf8(private_key)?)
            }
            (Err(_), Ok(private_key_path)) => Ok(std::fs::read_to_string(private_key_path)?),
            (Err(_), Err(_)) => Err(Error::msg("SF_PRIVATE_KEY_BASE64 or SF_PRIVATE_KEY_PATH not set!")),
        }?;

        Ok(Arc::new(SnowflakeConnector {
            account,
            user,
            role,
            warehouse,
            private_key,
            api: Mutex::new(None),
        }))
    }

    async fn init(&self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn plan(
        &self,
        addr: &Path,
        current: Option<Vec<u8>>,
        desired: Option<Vec<u8>>,
    ) -> Result<Vec<OpPlanOutput>, anyhow::Error> {
        tracing::info!("plan {:?} -? {:?}", current, desired);
        let addr = SnowflakeResourceAddress::from_path(addr)?;

        match &addr {
            SnowflakeResourceAddress::Database(name) => match (current, desired) {
                (None, None) => Ok(Vec::new()),
                (Some(_), None) => Ok(Vec::new()),
                (Some(_), Some(_)) => Ok(Vec::new()),
                (None, Some(definition)) => {
                    let definition = SQLDefinition::from_bytes(&addr, &definition);

                    let api = self.get_api(None, None).await?;

                    // tracing::info!("Statement: {}", statement);
                    // let res = api.exec(&statement.to_string()).await?;
                    // match res {
                    //     snowflake_api::QueryResult::Arrow(records) => {
                    //         all_results.push(format!("{:?}", records));
                    //     }
                    //     snowflake_api::QueryResult::Json(json) => {
                    //         all_results.push(format!("{:?}", json.value));
                    //     }
                    //     snowflake_api::QueryResult::Empty => {}
                    // }
                    // Ok(vec![Arc::new(SnowflakeConnectorOp::Execute(migration))])
                    Ok(vec![])
                }
            },
            _ => Ok(vec![]),
        }
    }

    async fn op_exec(&self, addr: &Path, op: &str) -> Result<OpExecOutput, anyhow::Error> {
        let op = SnowflakeConnectorOp::from_str(op)?;
        let addr = SnowflakeResourceAddress::from_path(addr)?;

        match addr {
            SnowflakeResourceAddress::Warehouse(name) => {
                let api = self.get_api(None, None).await?;
                match &op {
                    SnowflakeConnectorOp::Execute(def) => {
                        let res = api.exec(&def.statement.to_string()).await?;
                        // match res {
                        //     snowflake_api::QueryResult::Arrow(records) => {
                        //         println!("{:?}", records);
                        //     }
                        //     snowflake_api::QueryResult::Json(json) => {
                        //         println!("{:?}", json.value);
                        //     }
                        //     snowflake_api::QueryResult::Empty => {}
                        // }
                        Ok(OpExecOutput {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", def.statement)),
                        })
                    }
                    SnowflakeConnectorOp::Delete => {
                        let statement = format!("DROP WAREHOUSE {};", name);
                        let res = api.exec(&statement).await?;
                        Ok(OpExecOutput {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", statement)),
                        })
                    }
                }
            }
            SnowflakeResourceAddress::Database(name) => {
                let api = self.get_api(None, None).await?;
                match &op {
                    SnowflakeConnectorOp::Execute(def) => {
                        let res = api.exec(&def.statement.to_string()).await?;
                        match res {
                            snowflake_api::QueryResult::Arrow(records) => {
                                println!("{:?}", records);
                            }
                            snowflake_api::QueryResult::Json(json) => {
                                println!("{:?}", json.value);
                            }
                            snowflake_api::QueryResult::Empty => {}
                        }
                        Ok(OpExecOutput {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", def.statement)),
                        })
                    }
                    SnowflakeConnectorOp::Delete => {
                        let statement = format!("DROP DATABASE {};", name);
                        let res = api.exec(&statement).await?;
                        Ok(OpExecOutput {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", statement)),
                        })
                    }
                }
            }
            SnowflakeResourceAddress::Schema(database_name, name) => {
                let api = self.get_api(Some(&database_name), None).await?;
                match &op {
                    SnowflakeConnectorOp::Execute(def) => {
                        let res = api.exec(&def.statement.to_string()).await?;
                        match res {
                            snowflake_api::QueryResult::Arrow(records) => {
                                println!("{:?}", records);
                            }
                            snowflake_api::QueryResult::Json(json) => {
                                println!("{:?}", json.value);
                            }
                            snowflake_api::QueryResult::Empty => {}
                        }
                        Ok(OpExecOutput {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", def.statement)),
                        })
                    }
                    SnowflakeConnectorOp::Delete => {
                        let statement = &format!("DROP SCHEMA {}.{};", database_name, name);
                        let res = api.exec(&statement).await?;

                        Ok(OpExecOutput {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", statement)),
                        })
                    }
                }
            }
            SnowflakeResourceAddress::Table(database_name, schema_name, name) => {
                let api = self.get_api(Some(&database_name), Some(&schema_name)).await?;
                match &op {
                    SnowflakeConnectorOp::Execute(def) => {
                        let res = api.exec(&def.statement.to_string()).await?;
                        match res {
                            snowflake_api::QueryResult::Arrow(records) => {
                                println!("{:?}", records);
                            }
                            snowflake_api::QueryResult::Json(json) => {
                                println!("{:?}", json.value);
                            }
                            snowflake_api::QueryResult::Empty => {}
                        }
                        Ok(OpExecOutput {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", def.statement)),
                        })
                    }
                    SnowflakeConnectorOp::Delete => {
                        let statement = format!("DROP TABLE {}.{}.{};", database_name, schema_name, name);
                        let res = api.exec(&statement).await?;
                        Ok(OpExecOutput {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Success: {}", statement)),
                        })
                    }
                }
            }
        }
    }

    async fn get(&self, addr: &Path) -> Result<Option<GetResourceOutput>, anyhow::Error> {
        let addr = SnowflakeResourceAddress::from_path(addr)?;
        match &addr {
            addr => match &addr {
                SnowflakeResourceAddress::Warehouse(name) => {
                    let ddl = self.get_ddl("WAREHOUSE", &name).await?;
                    if let Some(ddl) = ddl {
                        get_resource_output!(SQLDefinition::from_bytes(addr, &ddl.as_bytes())?)
                    } else {
                        Ok(None)
                    }
                }
                SnowflakeResourceAddress::Database(name) => {
                    let ddl = self.get_ddl("DATABASE", &name).await?;
                    if let Some(ddl) = ddl {
                        get_resource_output!(SQLDefinition::from_bytes(addr, &ddl.as_bytes())?)
                    } else {
                        Ok(None)
                    }
                }
                SnowflakeResourceAddress::Schema(database_name, name) => {
                    let ddl = self.get_ddl("SCHEMA", &format!("{}.{}", database_name, name)).await?;
                    if let Some(ddl) = ddl {
                        get_resource_output!(SQLDefinition::from_bytes(addr, &ddl.as_bytes())?)
                    } else {
                        Ok(None)
                    }
                }
                SnowflakeResourceAddress::Table(database_name, schema_name, name) => {
                    let ddl = self
                        .get_ddl("TABLE", &format!("{}.{}.{}", database_name, schema_name, name))
                        .await?;
                    if let Some(ddl) = ddl {
                        get_resource_output!(SQLDefinition::from_bytes(addr, &ddl.as_bytes())?)
                    } else {
                        Ok(None)
                    }
                }
            },
        }
    }

    async fn list(&self, subpath: &Path) -> Result<Vec<PathBuf>, anyhow::Error> {
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

        Ok(results)
    }

    async fn eq(&self, addr: &Path, a: &[u8], b: &[u8]) -> anyhow::Result<bool> {
        Ok(a == b)
    }

    async fn diag(&self, addr: &Path, a: &[u8]) -> Result<DiagnosticOutput, anyhow::Error> {
        let snowflake_dialect = sqlparser::dialect::SnowflakeDialect;

        let ast = sqlparser::parser::Parser::parse_sql(&snowflake_dialect, &str::from_utf8(a)?);
        match ast {
            Ok(_) => return Ok(DiagnosticOutput { diagnostics: Vec::new() }),
            Err(e) => match e {
                sqlparser::parser::ParserError::TokenizerError(e) => {
                    return Ok(DiagnosticOutput {
                        diagnostics: vec![Diagnostic {
                            severity: DiagnosticSeverity::ERROR as u8,
                            span:     DiagnosticSpan {
                                start: DiagnosticPosition { line: 1, col: 1 },
                                end:   DiagnosticPosition { line: 1, col: 1 },
                            },
                            message:  e,
                        }],
                    });
                }
                sqlparser::parser::ParserError::ParserError(e) => {
                    return Ok(DiagnosticOutput {
                        diagnostics: vec![Diagnostic {
                            severity: DiagnosticSeverity::ERROR as u8,
                            span:     DiagnosticSpan {
                                start: DiagnosticPosition { line: 1, col: 1 },
                                end:   DiagnosticPosition { line: 1, col: 1 },
                            },
                            message:  e,
                        }],
                    });
                }
                sqlparser::parser::ParserError::RecursionLimitExceeded => {
                    return Ok(DiagnosticOutput {
                        diagnostics: vec![Diagnostic {
                            severity: DiagnosticSeverity::ERROR as u8,
                            span:     DiagnosticSpan {
                                start: DiagnosticPosition { line: 1, col: 1 },
                                end:   DiagnosticPosition { line: 1, col: 1 },
                            },
                            message:  "Recursion limit exceeded".into(),
                        }],
                    });
                }
            },
        }
    }
}

impl SnowflakeConnector {
    pub async fn get_api(&self, database: Option<&str>, schema: Option<&str>) -> Result<Arc<SnowflakeApi>, anyhow::Error> {
        if let Some(api) = &*self.api.lock().await {
            return Ok(api.clone());
        }

        let new_api = Arc::new(SnowflakeApi::with_certificate_auth(
            &self.account,
            Some(&self.warehouse),
            database,
            schema,
            &self.user,
            Some(&self.role),
            &self.private_key,
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
            tracing::warn!("SHOW DATABASES: {}", json_result.value);
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
            tracing::warn!("SHOW SCHEMAS: {}", json_result.value);
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
            tracing::warn!("SHOW TABLES: {}", json_result.value);
            for row in json_result.value.as_array().unwrap() {
                tables.push(row.as_array().unwrap()[1].as_str().unwrap().to_string());
            }
        }

        Ok(tables)
    }
}
