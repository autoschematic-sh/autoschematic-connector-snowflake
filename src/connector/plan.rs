use std::path::Path;

use autoschematic_core::{
    connector::{ConnectorOp, PlanResponseElement, Resource, ResourceAddress},
    connector_op,
    util::diff_ron_values,
};
use indexmap::IndexMap;

use crate::{addr::SnowflakeResourceAddress, connector::PrivilegeTargetKind, op::*, resource::*, util};

use crate::connector::SnowflakeConnector;

impl SnowflakeConnector {
    pub async fn do_plan(
        &self,
        addr: &Path,
        current: Option<Vec<u8>>,
        desired: Option<Vec<u8>>,
    ) -> Result<Vec<PlanResponseElement>, anyhow::Error> {
        let addr = SnowflakeResourceAddress::from_path(addr)?;

        let mut res = Vec::new();

        match &addr {
            SnowflakeResourceAddress::Warehouse { name } => match (current, desired) {
                (None, None) => Ok(Vec::new()),
                (Some(_), None) => {
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Delete,
                        format!("DROP WAREHOUSE `{}`", name)
                    ));
                    Ok(res)
                }
                (Some(_), Some(definition)) => {
                    let definition = SQLDefinition::from_bytes(&addr, &definition)?;
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Execute(definition),
                        format!("CREATE OR REPLACE WAREHOUSE `{}`", name)
                    ));
                    Ok(res)
                }
                (None, Some(definition)) => {
                    let definition = SQLDefinition::from_bytes(&addr, &definition)?;
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Execute(definition),
                        format!("CREATE OR REPLACE WAREHOUSE `{}`", name)
                    ));
                    Ok(res)
                }
            },
            SnowflakeResourceAddress::Database { name } => match (current, desired) {
                (None, None) => Ok(Vec::new()),
                (Some(_), None) => {
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Delete,
                        format!("DROP DATABASE `{}`", name)
                    ));
                    Ok(res)
                }
                (Some(_), Some(definition)) => {
                    let definition = SQLDefinition::from_bytes(&addr, &definition)?;
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Execute(definition),
                        format!("CREATE OR REPLACE DATABASE `{}`", name)
                    ));
                    Ok(res)
                }
                (None, Some(definition)) => {
                    let definition = SQLDefinition::from_bytes(&addr, &definition)?;
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Execute(definition),
                        format!("CREATE OR REPLACE DATABASE `{}`", name)
                    ));
                    Ok(res)
                }
            },
            SnowflakeResourceAddress::Schema { name, database } => match (current, desired) {
                (None, None) => Ok(Vec::new()),
                (Some(_), None) => {
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Delete,
                        format!("DROP SCHEMA `{database}.{name}`")
                    ));
                    Ok(res)
                }
                (Some(_), Some(definition)) => {
                    let definition = SQLDefinition::from_bytes(&addr, &definition)?;
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Execute(definition),
                        format!("CREATE OR REPLACE SCHEMA `{database}.{name}`")
                    ));
                    Ok(res)
                }
                (None, Some(definition)) => {
                    let definition = SQLDefinition::from_bytes(&addr, &definition)?;
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Execute(definition),
                        format!("CREATE OR REPLACE SCHEMA `{database}.{name}`")
                    ));
                    Ok(res)
                }
            },
            SnowflakeResourceAddress::Table { database, schema, name } => match (current, desired) {
                (None, None) => Ok(Vec::new()),
                (Some(_), None) => {
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Delete,
                        format!("DROP TABLE `{database}.{schema}.{name}`")
                    ));
                    Ok(res)
                }
                (Some(_), Some(definition)) => {
                    let definition = SQLDefinition::from_bytes(&addr, &definition)?;
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Execute(definition),
                        format!("CREATE OR REPLACE TABLE `{database}.{schema}.{name}`")
                    ));
                    Ok(res)
                }
                (None, Some(definition)) => {
                    let definition = SQLDefinition::from_bytes(&addr, &definition)?;
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Execute(definition),
                        format!("CREATE OR REPLACE TABLE `{database}.{schema}.{name}`")
                    ));
                    Ok(res)
                }
            },
            SnowflakeResourceAddress::FileFormat { database, schema, name } => match (current, desired) {
                (None, None) => Ok(Vec::new()),
                (Some(_), None) => {
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Delete,
                        format!("DROP FILE FORMAT `{database}.{schema}.{name}`")
                    ));
                    Ok(res)
                }
                (Some(_), Some(definition)) => {
                    let definition = SQLDefinition::from_bytes(&addr, &definition)?;
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Execute(definition),
                        format!("CREATE OR REPLACE FILE FORMAT `{database}.{schema}.{name}`")
                    ));
                    Ok(res)
                }
                (None, Some(definition)) => {
                    let definition = SQLDefinition::from_bytes(&addr, &definition)?;
                    res.push(connector_op!(
                        SnowflakeConnectorOp::Execute(definition),
                        format!("CREATE OR REPLACE FILE FORMAT `{database}.{schema}.{name}`")
                    ));
                    Ok(res)
                }
            },
            SnowflakeResourceAddress::User { name } => {
                match (current, desired) {
                    (None, None) => {}
                    (None, Some(new_user_bytes)) => {
                        let new_user: SnowflakeUser = SnowflakeUser::from_bytes(&addr, &new_user_bytes)?;
                        let roles_to_grant = new_user.granted_roles.clone();
                        let grants_to_apply = new_user.grants.clone();
                        res.push(connector_op!(
                            SnowflakeConnectorOp::CreateUser(Box::new(new_user.clone())),
                            format!("Create Snowflake user `{}`", name)
                        ));
                        for role in roles_to_grant {
                            res.push(connector_op!(
                                SnowflakeConnectorOp::GrantRoleToUser(role.clone()),
                                format!("Grant role `{}` to user `{}`", role, name)
                            ));
                        }
                        Self::extend_privilege_plan(
                            &mut res,
                            PrivilegeTargetKind::User,
                            name,
                            &IndexMap::new(),
                            &grants_to_apply,
                            false,
                        )?;
                    }
                    (Some(_old_user_bytes), None) => {
                        res.push(connector_op!(
                            SnowflakeConnectorOp::DropUser,
                            format!("Drop Snowflake user `{}`", name)
                        ));
                    }
                    (Some(old_user_bytes), Some(new_user_bytes)) => {
                        let old_user: SnowflakeUser = SnowflakeUser::from_bytes(&addr, &old_user_bytes)?;
                        let new_user: SnowflakeUser = SnowflakeUser::from_bytes(&addr, &new_user_bytes)?;

                        let old_props = util::user_properties_only(&old_user);
                        let new_props = util::user_properties_only(&new_user);
                        if old_props != new_props {
                            let diff = diff_ron_values(&old_props, &new_props).unwrap_or_default();
                            res.push(connector_op!(
                                SnowflakeConnectorOp::AlterUser(Box::new(old_user.clone()), Box::new(new_user.clone())),
                                format!("Alter Snowflake user `{name}\n{diff}`")
                            ));
                        }

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

                        Self::extend_privilege_plan(
                            &mut res,
                            PrivilegeTargetKind::User,
                            name,
                            &old_user.grants,
                            &new_user.grants,
                            false,
                        )?;
                    }
                }
                Ok(res)
            }

            SnowflakeResourceAddress::Role { name } => {
                match (current, desired) {
                    (None, None) => {}
                    (None, Some(new_role_bytes)) => {
                        let new_role: SnowflakeRole = SnowflakeRole::from_bytes(&addr, &new_role_bytes)?;
                        let roles_to_grant = new_role.granted_roles.clone();
                        let grants_to_apply = new_role.grants.clone();
                        let future_grants_to_apply = new_role.future_grants.clone();
                        let desired_owner = new_role.owner.clone();
                        let session_role = self.current_session_role().await;
                        res.push(connector_op!(
                            SnowflakeConnectorOp::CreateRole(Box::new(new_role.clone())),
                            format!("Create Snowflake role `{}`", name)
                        ));
                        for role in roles_to_grant {
                            res.push(connector_op!(
                                SnowflakeConnectorOp::GrantRoleToRole(role.clone()),
                                format!("Grant role `{}` to role `{}`", role, name)
                            ));
                        }
                        Self::extend_privilege_plan(
                            &mut res,
                            PrivilegeTargetKind::Role,
                            name,
                            &IndexMap::new(),
                            &grants_to_apply,
                            false,
                        )?;
                        Self::extend_privilege_plan(
                            &mut res,
                            PrivilegeTargetKind::Role,
                            name,
                            &IndexMap::new(),
                            &future_grants_to_apply,
                            true,
                        )?;

                        if let Some(owner) = desired_owner
                            && session_role.as_deref() != Some(owner.as_str())
                        {
                            res.push(connector_op!(
                                SnowflakeConnectorOp::TransferRoleOwnership(owner.clone()),
                                format!("Transfer Snowflake role `{}` ownership to `{}`", name, owner)
                            ));
                        }
                    }
                    (Some(_old_role_bytes), None) => {
                        res.push(connector_op!(
                            SnowflakeConnectorOp::DropRole,
                            format!("Drop Snowflake role `{}`", name)
                        ));
                    }
                    (Some(old_role_bytes), Some(new_role_bytes)) => {
                        let old_role: SnowflakeRole = SnowflakeRole::from_bytes(&addr, &old_role_bytes)?;
                        let new_role: SnowflakeRole = SnowflakeRole::from_bytes(&addr, &new_role_bytes)?;

                        let old_props = util::role_properties_only(&old_role);
                        let new_props = util::role_properties_only(&new_role);

                        if old_props != new_props {
                            let diff = diff_ron_values(&old_props, &new_props).unwrap_or_default();
                            res.push(connector_op!(
                                SnowflakeConnectorOp::AlterRole(Box::new(old_role.clone()), Box::new(new_role.clone())),
                                format!("Alter Snowflake role `{name}`\n{diff}")
                            ));
                        }

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

                        Self::extend_privilege_plan(
                            &mut res,
                            PrivilegeTargetKind::Role,
                            name,
                            &old_role.grants,
                            &new_role.grants,
                            false,
                        )?;
                        Self::extend_privilege_plan(
                            &mut res,
                            PrivilegeTargetKind::Role,
                            name,
                            &old_role.future_grants,
                            &new_role.future_grants,
                            true,
                        )?;

                        if old_role.owner != new_role.owner
                            && let Some(owner) = new_role.owner.clone()
                        {
                            res.push(connector_op!(
                                SnowflakeConnectorOp::TransferRoleOwnership(owner.clone()),
                                format!("Transfer Snowflake role `{}` ownership to `{}`", name, owner)
                            ));
                        }
                    }
                }
                Ok(res)
            }
        }
    }
}
