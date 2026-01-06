use std::path::{Path, PathBuf};

use autoschematic_core::{connector::ResourceAddress, error_util::invalid_addr_path};

#[derive(Clone, Debug)]
pub enum SnowflakeResourceAddress {
    Warehouse { name: String },
    Database { name: String },
    Schema { database: String, name: String },
    Table { database: String, schema: String, name: String },
    // RBAC resources
    User { name: String },
    Role { name: String },
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
            SnowflakeResourceAddress::Warehouse { name } => PathBuf::from(format!("snowflake/warehouses/{}.sql", name)),
            SnowflakeResourceAddress::Database { name } => PathBuf::from(format!("snowflake/databases/{}/database.sql", name)),
            SnowflakeResourceAddress::Schema { database, name } => {
                PathBuf::from(format!("snowflake/databases/{}/{}/schema.sql", database, name))
            }
            SnowflakeResourceAddress::Table { database, schema, name } => {
                PathBuf::from(format!("snowflake/databases/{}/{}/{}/table.sql", database, schema, name))
            }
            SnowflakeResourceAddress::User { name } => PathBuf::from(format!("snowflake/users/{}.ron", name)),
            SnowflakeResourceAddress::Role { name } => PathBuf::from(format!("snowflake/roles/{}.ron", name)),
        }
    }

    fn from_path(path: &Path) -> Result<Self, anyhow::Error> {
        let path_components: Vec<&str> = path
            .components()
            .into_iter()
            .map(|s| s.as_os_str().to_str().unwrap())
            .collect();

        match path_components[..] {
            ["snowflake", "warehouses", name] if name.ends_with(".sql") => Ok(SnowflakeResourceAddress::Warehouse {
                name: strip_sql_suffix(name),
            }),
            ["snowflake", "databases", name, "database.sql"] => {
                Ok(SnowflakeResourceAddress::Database { name: name.to_string() })
            }
            ["snowflake", "databases", database, name, "schema.sql"] => Ok(SnowflakeResourceAddress::Schema {
                database: database.to_string(),
                name: name.to_string(),
            }),
            ["snowflake", "databases", database, schema, name, "table.sql"] => Ok(SnowflakeResourceAddress::Table {
                database: database.to_string(),
                schema: schema.to_string(),
                name: name.to_string(),
            }),
            ["snowflake", "users", name] if name.ends_with(".ron") => {
                Ok(SnowflakeResourceAddress::User{name: strip_ron_suffix(name)})
            }
            ["snowflake", "roles", name] if name.ends_with(".ron") => {
                Ok(SnowflakeResourceAddress::Role{name: strip_ron_suffix(name)})
            }
            _ => Err(invalid_addr_path(path)),
        }
    }
}
