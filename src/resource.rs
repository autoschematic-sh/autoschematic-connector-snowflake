use autoschematic_core::{
    connector::{Resource, ResourceAddress},
    util::RON,
};
use indexmap::IndexSet;
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
    #[serde(default, skip_serializing_if = "IndexSet::is_empty")]
    pub granted_roles: IndexSet<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SnowflakeRole {
    /// Comment/description for the role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Roles granted to this role (i.e., roles this role inherits privileges from).
    #[serde(default, skip_serializing_if = "IndexSet::is_empty")]
    pub granted_roles: IndexSet<String>,
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
