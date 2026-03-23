use std::{collections::HashMap, path::Path};

use anyhow::bail;
use autoschematic_core::connector::{ConnectorOp, OpExecResponse, ResourceAddress};

use crate::{
    addr::SnowflakeResourceAddress,
    op::*,
    util::sql::{self, build_alter_role_sql, build_create_role_sql, build_transfer_role_ownership_sql},
};

use crate::connector::SnowflakeConnector;

impl SnowflakeConnector {
    pub async fn do_op_exec(&self, addr: &Path, op: &str) -> Result<OpExecResponse, anyhow::Error> {
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
                        let statement = format!("DROP USER \"{}\";", name);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Dropped Snowflake user `{}`", name)),
                        })
                    }
                    SnowflakeConnectorOp::GrantRoleToUser(role_name) => {
                        let statement = format!("GRANT ROLE \"{}\" TO USER \"{}\";", role_name, name);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Granted role `{}` to user `{}`", role_name, name)),
                        })
                    }
                    SnowflakeConnectorOp::RevokeRoleFromUser(role_name) => {
                        let statement = format!("REVOKE ROLE \"{}\" FROM USER \"{}\";", role_name, name);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Revoked role `{}` from user `{}`", role_name, name)),
                        })
                    }
                    SnowflakeConnectorOp::GrantPrivilege {
                        privilege,
                        object_type,
                        future,
                    } => {
                        let statement = sql::build_grant_privilege_sql("USER", &name, &privilege, &object_type, future)?;
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!(
                                "Granted {} on {} to user `{}`",
                                privilege,
                                Self::describe_object_type(&object_type, future),
                                name
                            )),
                        })
                    }
                    SnowflakeConnectorOp::RevokePrivilege {
                        privilege,
                        object_type,
                        future,
                    } => {
                        let statement = sql::build_revoke_privilege_sql("USER", &name, &privilege, &object_type, future)?;
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!(
                                "Revoked {} on {} from user `{}`",
                                privilege,
                                Self::describe_object_type(&object_type, future),
                                name
                            )),
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
                        let statement = build_alter_role_sql(&name, &new_role);
                        api.exec(&statement).await?;

                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Altered Snowflake role `{}`", name)),
                        })
                    }
                    SnowflakeConnectorOp::DropRole => {
                        let statement = format!("DROP ROLE \"{}\";", name);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Dropped Snowflake role `{}`", name)),
                        })
                    }
                    SnowflakeConnectorOp::GrantRoleToRole(role_name) => {
                        let statement = format!("GRANT ROLE \"{}\" TO ROLE \"{}\";", role_name, name);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Granted role `{}` to role `{}`", role_name, name)),
                        })
                    }
                    SnowflakeConnectorOp::RevokeRoleFromRole(role_name) => {
                        let statement = format!("REVOKE ROLE \"{}\" FROM ROLE \"{}\";", role_name, name);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Revoked role `{}` from role `{}`", role_name, name)),
                        })
                    }
                    SnowflakeConnectorOp::GrantPrivilege {
                        privilege,
                        object_type,
                        future,
                    } => {
                        let statement = sql::build_grant_privilege_sql("ROLE", &name, &privilege, &object_type, future)?;
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!(
                                "Granted {} on {} to role `{}`",
                                privilege,
                                Self::describe_object_type(&object_type, future),
                                name
                            )),
                        })
                    }
                    SnowflakeConnectorOp::RevokePrivilege {
                        privilege,
                        object_type,
                        future,
                    } => {
                        let statement = sql::build_revoke_privilege_sql("ROLE", &name, &privilege, &object_type, future)?;
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!(
                                "Revoked {} on {} from role `{}`",
                                privilege,
                                Self::describe_object_type(&object_type, future),
                                name
                            )),
                        })
                    }
                    SnowflakeConnectorOp::TransferRoleOwnership(owner) => {
                        let statement = build_transfer_role_ownership_sql(&name, &owner);
                        api.exec(&statement).await?;
                        Ok(OpExecResponse {
                            outputs: Some(HashMap::new()),
                            friendly_message: Some(format!("Transferred Snowflake role `{}` ownership to `{}`", name, owner)),
                        })
                    }
                    _ => bail!("Invalid operation for Role address"),
                }
            }
        }
    }
}
