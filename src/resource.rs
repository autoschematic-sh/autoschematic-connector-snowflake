use autoschematic_core::macros::FieldTypes;
use autoschematic_core::{
    connector::{Resource, ResourceAddress},
    util::RON,
};
use autoschematic_macros::FieldTypes;
use documented::{Documented, DocumentedFields};
use indexmap::{IndexMap, IndexSet};
use ron::ser::PrettyConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SQLDefinition {
    pub statement: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
#[allow(non_camel_case_types)]
/// Represents a Snowflake object_type.
pub enum ObjectType {
    /// The top-level Snowflake account object. Global privileges (e.g. CREATE DATABASE,
    /// MANAGE GRANTS) are granted at this level.
    ACCOUNT(String),
    /// An account-level integration that stores metadata about how table data is organized
    /// in an external catalog (e.g. AWS Glue, Apache Iceberg REST) for use with Iceberg tables.
    CATALOG_INTEGRATION(String),
    /// A set of compute resources for running Snowpark Container Services workloads.
    /// Supports MODIFY, MONITOR, OPERATE, and USAGE privileges.
    COMPUTE_POOL(String),
    /// A top-level container for schemas, tables, views, and other schema-scoped objects.
    /// Supports privileges such as CREATE SCHEMA, MODIFY, MONITOR, and USAGE.
    DATABASE(String),
    /// A role scoped to a single database, used to manage permissions on objects within
    /// that database. Unlike account-level roles, database roles cannot be granted to users directly.
    DATABASE_ROLE(String),
    /// A table whose contents are automatically refreshed based on a specified query.
    /// Supports MONITOR, OPERATE, and SELECT privileges.
    DYNAMIC_TABLE(String),
    /// A special table used to store log, trace, and metric data from Snowflake operations
    /// and Snowpark workloads. Supports SELECT, DELETE, TRUNCATE, and other table-level privileges.
    EVENT_TABLE(String),
    /// An account-level object that connects Snowflake to external cloud storage (e.g. S3, GCS,
    /// Azure Blob) for reading and writing Apache Iceberg table data and metadata.
    EXTERNAL_VOLUME(String),
    /// A user-defined function (UDF) or external function defined in a schema. Argument data
    /// types must be specified when granting privileges on individual functions.
    FUNCTION(String),
    /// A container registry for storing and managing OCI images used by Snowpark Container Services.
    IMAGE_REPOSITORY(String),
    /// A reader account created and managed by a data provider for sharing data with consumers
    /// who do not have their own Snowflake account. The provider assumes all credit charges.
    MANAGED_ACCOUNT(String),
    /// A set of rules that control inbound network traffic to a Snowflake account, user, or
    /// security integration based on IP address allow/block lists.
    NETWORK_POLICY(String),
    /// An interactive, cell-based document within a schema for exploratory data analysis,
    /// combining SQL, Python, and Markdown.
    NOTEBOOK(String),
    /// An account-level integration that provides an interface between Snowflake and third-party
    /// messaging services such as cloud message queues, email, and webhooks.
    NOTIFICATION_INTEGRATION(String),
    /// A schema-level object that defines a Snowpipe configuration for automated, continuous
    /// data loading from staged files into a target table.
    PIPE(String),
    /// A stored procedure defined in a schema. Like functions, argument data types must be
    /// specified when granting privileges on individual procedures.
    PROCEDURE(String),
    /// An account-level entity to which privileges on securable objects can be granted. Roles
    /// are in turn assigned to users or other roles to form a role hierarchy.
    ROLE(String),
    /// A logical container within a database that groups tables, views, stages, functions,
    /// and other schema-scoped objects.
    SCHEMA(String),
    /// A long-running containerized application managed by Snowpark Container Services,
    /// deployed within a compute pool.
    SERVICE(String),
    /// A named storage location for data files, either internal (managed by Snowflake) or
    /// external (referencing cloud storage). Used for bulk data loading and unloading.
    STAGE(String),
    /// A schema-level object that records DML changes (inserts, updates, deletes) made to a
    /// table, enabling change data capture (CDC) workflows.
    STREAM(String),
    /// A structured data store within a schema consisting of rows and columns. Supports
    /// SELECT, INSERT, UPDATE, DELETE, TRUNCATE, and other DML privileges.
    TABLE(String),
    /// A schema-level object that defines a scheduled or triggered execution of a SQL statement
    /// or stored procedure. Supports MONITOR and OPERATE privileges.
    TASK(String),
    /// A user-defined function written in a supported language (SQL, JavaScript, Python, Java,
    /// or Scala) and registered in a schema.
    USER_DEFINED_FUNCTION(String),
    /// A named, schema-level object defined by a SQL query. Views can be standard or secure;
    /// secure views hide their definition from unauthorized users.
    VIEW(String),
    /// A named cluster of compute resources (virtual warehouse) used to execute queries and DML
    /// operations. Supports MODIFY, MONITOR, OPERATE, and USAGE privileges.
    WAREHOUSE(String),
}

impl ObjectType {
    pub fn from_str(s: &str, inner: &str) -> Option<ObjectType> {
        let res = match s {
            "ACCOUNT" => ObjectType::ACCOUNT(inner.to_string()),
            "CATALOG INTEGRATION" => ObjectType::CATALOG_INTEGRATION(inner.to_string()),
            "COMPUTE POOL" => ObjectType::COMPUTE_POOL(inner.to_string()),
            "DATABASE" => ObjectType::DATABASE(inner.to_string()),
            "DATABASE_ROLE" => ObjectType::DATABASE_ROLE(inner.to_string()),
            "DYNAMIC TABLE" => ObjectType::DYNAMIC_TABLE(inner.to_string()),
            "EVENT TABLE" => ObjectType::EVENT_TABLE(inner.to_string()),
            "EXTERNAL_VOLUME" => ObjectType::EXTERNAL_VOLUME(inner.to_string()),
            "FUNCTION" => ObjectType::FUNCTION(inner.to_string()),
            "IMAGE REPOSITORY" => ObjectType::IMAGE_REPOSITORY(inner.to_string()),
            "MANAGED ACCOUNT" => ObjectType::MANAGED_ACCOUNT(inner.to_string()),
            "NETWORK_POLICY" => ObjectType::NETWORK_POLICY(inner.to_string()),
            "NOTEBOOK" => ObjectType::NOTEBOOK(inner.to_string()),
            "NOTIFICATION INTEGRATION" => ObjectType::NOTIFICATION_INTEGRATION(inner.to_string()),
            "PIPE" => ObjectType::PIPE(inner.to_string()),
            "PROCEDURE" => ObjectType::PROCEDURE(inner.to_string()),
            "ROLE" => ObjectType::ROLE(inner.to_string()),
            "SCHEMA" => ObjectType::SCHEMA(inner.to_string()),
            "SERVICE" => ObjectType::SERVICE(inner.to_string()),
            "STAGE" => ObjectType::STAGE(inner.to_string()),
            "STREAM" => ObjectType::STREAM(inner.to_string()),
            "TABLE" => ObjectType::TABLE(inner.to_string()),
            "TASK" => ObjectType::TASK(inner.to_string()),
            "USER DEFINED FUNCTION" => ObjectType::USER_DEFINED_FUNCTION(inner.to_string()),
            "VIEW" => ObjectType::VIEW(inner.to_string()),
            "WAREHOUSE" => ObjectType::WAREHOUSE(inner.to_string()),

            _ => return None,
        };
        Some(res)
    }
}

/// Represents a Snowflake user.
/// Properties map to Snowflake's ALTER USER / CREATE USER parameters.
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Documented, DocumentedFields, FieldTypes)]
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
    #[serde(skip)]
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
    #[serde(default, skip_serializing_if = "IndexSet::is_empty")]
    pub granted_roles: IndexSet<String>,
    /// Object grants granted to this user.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub grants: IndexMap<String, Vec<ObjectType>>,
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

fn skip_owner(owner: &Option<String>) -> bool {
    match owner {
        Some(s) if s == "ACCOUNTADMIN" => true,
        None => true,
        _ => false,
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Documented, DocumentedFields, FieldTypes)]
#[serde(deny_unknown_fields)]
/// Represents a Snowflake role.
/// Properties map to Snowflake's ALTER ROLE / CREATE ROLE parameters.
pub struct SnowflakeRole {
    /// Owner of the role.
    #[serde(skip_serializing_if = "skip_owner")]
    pub owner: Option<String>,
    /// Comment/description for the role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Roles granted to this role (i.e., roles this role can assume).
    #[serde(default, skip_serializing_if = "IndexSet::is_empty")]
    pub granted_roles: IndexSet<String>,

    /// Object grants granted to this role.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub grants: IndexMap<String, Vec<ObjectType>>,

    /// Future grants granted to this role.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub future_grants: IndexMap<String, Vec<ObjectType>>,
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
