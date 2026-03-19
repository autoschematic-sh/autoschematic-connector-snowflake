use autoschematic_core::connector::ConnectorOp;
use serde::{Deserialize, Serialize};

use crate::resource::*;

#[derive(Debug, Serialize, Deserialize)]
pub enum SnowflakeConnectorOp {
    Execute(SQLDefinition),
    Delete,
    // User operations
    CreateUser(SnowflakeUser),
    AlterUser(Box<SnowflakeUser>, Box<SnowflakeUser>), // (old, new)
    DropUser,
    // Role operations
    CreateRole(SnowflakeRole),
    AlterRole(Box<SnowflakeRole>, Box<SnowflakeRole>), // (old, new)
    DropRole,
    // Role grant operations - explicit ops for granting/revoking roles
    GrantRoleToUser(String),    // role_name to grant to user at addr
    RevokeRoleFromUser(String), // role_name to revoke from user at addr
    GrantRoleToRole(String),    // role_name to grant to role at addr
    RevokeRoleFromRole(String), // role_name to revoke from role at addr
    // Object privilege operations
    GrantPrivilege {
        privilege: String,
        object_type: ObjectType,
        future: bool,
    },
    RevokePrivilege {
        privilege: String,
        object_type: ObjectType,
        future: bool,
    },
    TransferRoleOwnership(String), // owner role name
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
