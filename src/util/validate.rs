use sqlparser::ast::{self, Statement};

use crate::addr::SnowflakeResourceAddress;

pub fn validate_ddl_target(addr: SnowflakeResourceAddress, statement: &ast::Statement) -> anyhow::Result<()> {
    match addr {
        SnowflakeResourceAddress::Warehouse { name } => {
        }
        SnowflakeResourceAddress::Database { name } => todo!(),
        SnowflakeResourceAddress::Schema { database, name } => todo!(),
        SnowflakeResourceAddress::Table { database, schema, name } => todo!(),
        SnowflakeResourceAddress::User { name } => todo!(),
        SnowflakeResourceAddress::Role { name } => todo!(),
    }

    Ok(())
}
