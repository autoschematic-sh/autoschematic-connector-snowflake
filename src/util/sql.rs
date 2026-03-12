use anyhow::{Result, bail};

use crate::resource::{ObjectType, SnowflakeRole, SnowflakeUser};

fn escape_string(value: &str) -> String {
    value.replace('\'', "''")
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn current_grant_object_clause(object_type: &ObjectType) -> (&'static str, Option<&str>) {
    match object_type {
        ObjectType::ACCOUNT(_) => ("ACCOUNT", None),
        ObjectType::CATALOG_INTEGRATION(name) => ("CATALOG INTEGRATION", Some(name.as_str())),
        ObjectType::COMPUTE_POOL(name) => ("COMPUTE POOL", Some(name.as_str())),
        ObjectType::DATABASE(name) => ("DATABASE", Some(name.as_str())),
        ObjectType::DATABASE_ROLE(name) => ("DATABASE ROLE", Some(name.as_str())),
        ObjectType::DYNAMIC_TABLE(name) => ("DYNAMIC TABLE", Some(name.as_str())),
        ObjectType::EVENT_TABLE(name) => ("EVENT TABLE", Some(name.as_str())),
        ObjectType::EXTERNAL_VOLUME(name) => ("EXTERNAL VOLUME", Some(name.as_str())),
        ObjectType::FUNCTION(name) => ("FUNCTION", Some(name.as_str())),
        ObjectType::IMAGE_REPOSITORY(name) => ("IMAGE REPOSITORY", Some(name.as_str())),
        ObjectType::MANAGED_ACCOUNT(name) => ("MANAGED ACCOUNT", Some(name.as_str())),
        ObjectType::NETWORK_POLICY(name) => ("NETWORK POLICY", Some(name.as_str())),
        ObjectType::NOTEBOOK(name) => ("NOTEBOOK", Some(name.as_str())),
        ObjectType::NOTIFICATION_INTEGRATION(name) => ("NOTIFICATION INTEGRATION", Some(name.as_str())),
        ObjectType::PIPE(name) => ("PIPE", Some(name.as_str())),
        ObjectType::PROCEDURE(name) => ("PROCEDURE", Some(name.as_str())),
        ObjectType::ROLE(name) => ("ROLE", Some(name.as_str())),
        ObjectType::SCHEMA(name) => ("SCHEMA", Some(name.as_str())),
        ObjectType::SERVICE(name) => ("SERVICE", Some(name.as_str())),
        ObjectType::STAGE(name) => ("STAGE", Some(name.as_str())),
        ObjectType::STREAM(name) => ("STREAM", Some(name.as_str())),
        ObjectType::TABLE(name) => ("TABLE", Some(name.as_str())),
        ObjectType::TASK(name) => ("TASK", Some(name.as_str())),
        ObjectType::USER_DEFINED_FUNCTION(name) => ("FUNCTION", Some(name.as_str())),
        ObjectType::VIEW(name) => ("VIEW", Some(name.as_str())),
        ObjectType::WAREHOUSE(name) => ("WAREHOUSE", Some(name.as_str())),
    }
}

fn future_grant_object_clause(object_type: &ObjectType) -> Result<(&'static str, &'static str, &str)> {
    match object_type {
        ObjectType::SCHEMA(scope) => Ok(("SCHEMAS", "DATABASE", scope.as_str())),
        ObjectType::DYNAMIC_TABLE(scope) => Ok(("DYNAMIC TABLES", "SCHEMA", scope.as_str())),
        ObjectType::EVENT_TABLE(scope) => Ok(("EVENT TABLES", "SCHEMA", scope.as_str())),
        ObjectType::FUNCTION(scope) => Ok(("FUNCTIONS", "SCHEMA", scope.as_str())),
        ObjectType::IMAGE_REPOSITORY(scope) => Ok(("IMAGE REPOSITORIES", "SCHEMA", scope.as_str())),
        ObjectType::NOTEBOOK(scope) => Ok(("NOTEBOOKS", "SCHEMA", scope.as_str())),
        ObjectType::PIPE(scope) => Ok(("PIPES", "SCHEMA", scope.as_str())),
        ObjectType::PROCEDURE(scope) => Ok(("PROCEDURES", "SCHEMA", scope.as_str())),
        ObjectType::SERVICE(scope) => Ok(("SERVICES", "SCHEMA", scope.as_str())),
        ObjectType::STAGE(scope) => Ok(("STAGES", "SCHEMA", scope.as_str())),
        ObjectType::STREAM(scope) => Ok(("STREAMS", "SCHEMA", scope.as_str())),
        ObjectType::TABLE(scope) => Ok(("TABLES", "SCHEMA", scope.as_str())),
        ObjectType::TASK(scope) => Ok(("TASKS", "SCHEMA", scope.as_str())),
        ObjectType::USER_DEFINED_FUNCTION(scope) => Ok(("FUNCTIONS", "SCHEMA", scope.as_str())),
        ObjectType::VIEW(scope) => Ok(("VIEWS", "SCHEMA", scope.as_str())),
        _ => bail!("unsupported Snowflake future grant object type: {:?}", object_type),
    }
}

fn privilege_target_clause(target_keyword: &str, target_name: &str) -> String {
    format!("{target_keyword} {}", quote_identifier(target_name))
}

pub fn build_create_role_sql(name: &str, role: &SnowflakeRole) -> String {
    let mut sql = format!("CREATE ROLE {}", quote_identifier(name));

    if let Some(ref comment) = role.comment {
        sql.push_str(&format!(" COMMENT = '{}'", escape_string(comment)));
    }

    sql.push(';');
    sql
}

pub fn build_alter_role_sql(name: &str, role: &SnowflakeRole) -> String {
    if let Some(ref comment) = role.comment {
        format!(
            "ALTER ROLE {} SET COMMENT = '{}';",
            quote_identifier(name),
            escape_string(comment)
        )
    } else {
        format!("ALTER ROLE {} UNSET COMMENT;", quote_identifier(name))
    }
}

pub fn build_transfer_role_ownership_sql(name: &str, owner: &str) -> String {
    format!(
        "GRANT OWNERSHIP ON ROLE {} TO ROLE {} COPY CURRENT GRANTS;",
        quote_identifier(name),
        quote_identifier(owner)
    )
}

pub fn build_create_user_sql(name: &str, user: &SnowflakeUser) -> String {
    let mut sql = format!("CREATE USER {}", quote_identifier(name));
    let mut props = Vec::new();

    if let Some(ref login_name) = user.login_name {
        props.push(format!("LOGIN_NAME = '{}'", escape_string(login_name)));
    }
    if let Some(ref display_name) = user.display_name {
        props.push(format!("DISPLAY_NAME = '{}'", escape_string(display_name)));
    }
    if let Some(ref first_name) = user.first_name {
        props.push(format!("FIRST_NAME = '{}'", escape_string(first_name)));
    }
    if let Some(ref last_name) = user.last_name {
        props.push(format!("LAST_NAME = '{}'", escape_string(last_name)));
    }
    if let Some(ref email) = user.email {
        props.push(format!("EMAIL = '{}'", escape_string(email)));
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
            props.push(format!(
                "DEFAULT_SECONDARY_ROLES = ('{}')",
                escape_string(default_secondary_roles)
            ));
        } else {
            props.push(format!("DEFAULT_SECONDARY_ROLES = ({})", default_secondary_roles));
        }
    }
    if user.disabled {
        props.push("DISABLED = TRUE".to_string());
    }
    if let Some(ref rsa_public_key) = user.rsa_public_key {
        props.push(format!("RSA_PUBLIC_KEY = '{}'", escape_string(rsa_public_key)));
    }
    if let Some(ref rsa_public_key_2) = user.rsa_public_key_2 {
        props.push(format!("RSA_PUBLIC_KEY_2 = '{}'", escape_string(rsa_public_key_2)));
    }
    if let Some(ref comment) = user.comment {
        props.push(format!("COMMENT = '{}'", escape_string(comment)));
    }

    if !props.is_empty() {
        sql.push(' ');
        sql.push_str(&props.join(" "));
    }

    sql.push(';');
    sql
}

/// Build ALTER USER SQL statement from SnowflakeUser (sets all properties)
pub fn build_alter_user_sql(name: &str, user: &SnowflakeUser) -> String {
    let mut sql = format!("ALTER USER {} SET", quote_identifier(name));
    let mut props = Vec::new();

    // For ALTER USER, we need to set all properties to their desired values
    if let Some(ref login_name) = user.login_name {
        props.push(format!("LOGIN_NAME = '{}'", escape_string(login_name)));
    }
    if let Some(ref display_name) = user.display_name {
        props.push(format!("DISPLAY_NAME = '{}'", escape_string(display_name)));
    }
    if let Some(ref first_name) = user.first_name {
        props.push(format!("FIRST_NAME = '{}'", escape_string(first_name)));
    }
    if let Some(ref last_name) = user.last_name {
        props.push(format!("LAST_NAME = '{}'", escape_string(last_name)));
    }
    if let Some(ref email) = user.email {
        props.push(format!("EMAIL = '{}'", escape_string(email)));
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
            props.push(format!(
                "DEFAULT_SECONDARY_ROLES = ('{}')",
                escape_string(default_secondary_roles)
            ));
        } else {
            props.push(format!("DEFAULT_SECONDARY_ROLES = ({})", default_secondary_roles));
        }
    }

    props.push(format!("DISABLED = {}", if user.disabled { "TRUE" } else { "FALSE" }));

    if let Some(ref rsa_public_key) = user.rsa_public_key {
        props.push(format!("RSA_PUBLIC_KEY = '{}'", escape_string(rsa_public_key)));
    }
    if let Some(ref rsa_public_key_2) = user.rsa_public_key_2 {
        props.push(format!("RSA_PUBLIC_KEY_2 = '{}'", escape_string(rsa_public_key_2)));
    }
    if let Some(ref comment) = user.comment {
        props.push(format!("COMMENT = '{}'", escape_string(comment)));
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

pub fn build_grant_privilege_sql(
    target_keyword: &str,
    target_name: &str,
    privilege: &str,
    object_type: &ObjectType,
    future: bool,
) -> Result<String> {
    let target_clause = privilege_target_clause(target_keyword, target_name);

    if future {
        let (object_plural, scope_keyword, scope_name) = future_grant_object_clause(object_type)?;
        return Ok(format!(
            "GRANT {privilege} ON FUTURE {object_plural} IN {scope_keyword} {scope_name} TO {target_clause};"
        ));
    }

    let (object_keyword, object_name) = current_grant_object_clause(object_type);

    Ok(match object_name {
        Some(object_name) => {
            format!("GRANT {privilege} ON {object_keyword} {object_name} TO {target_clause};")
        }
        None => format!("GRANT {privilege} ON {object_keyword} TO {target_clause};"),
    })
}

pub fn build_revoke_privilege_sql(
    target_keyword: &str,
    target_name: &str,
    privilege: &str,
    object_type: &ObjectType,
    future: bool,
) -> Result<String> {
    let target_clause = privilege_target_clause(target_keyword, target_name);

    if future {
        let (object_plural, scope_keyword, scope_name) = future_grant_object_clause(object_type)?;
        return Ok(format!(
            "REVOKE {privilege} ON FUTURE {object_plural} IN {scope_keyword} {scope_name} FROM {target_clause};"
        ));
    }

    let (object_keyword, object_name) = current_grant_object_clause(object_type);

    Ok(match object_name {
        Some(object_name) => {
            format!("REVOKE {privilege} ON {object_keyword} {object_name} FROM {target_clause};")
        }
        None => format!("REVOKE {privilege} ON {object_keyword} FROM {target_clause};"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_current_grant_sql_for_role() {
        let sql = build_grant_privilege_sql(
            "ROLE",
            "ANALYST",
            "SELECT",
            &ObjectType::TABLE("RAW.PUBLIC.EVENTS".into()),
            false,
        )
        .unwrap();

        assert_eq!(sql, "GRANT SELECT ON TABLE RAW.PUBLIC.EVENTS TO ROLE \"ANALYST\";");
    }

    #[test]
    fn builds_future_grant_sql_for_schema_scoped_objects() {
        let sql = build_grant_privilege_sql("ROLE", "ANALYST", "SELECT", &ObjectType::VIEW("RAW.PUBLIC".into()), true).unwrap();

        assert_eq!(sql, "GRANT SELECT ON FUTURE VIEWS IN SCHEMA RAW.PUBLIC TO ROLE \"ANALYST\";");
    }

    #[test]
    fn rejects_unsupported_future_grant_types() {
        let err = build_grant_privilege_sql(
            "ROLE",
            "ANALYST",
            "USAGE",
            &ObjectType::WAREHOUSE("TRANSFORMING".into()),
            true,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unsupported Snowflake future grant object type"));
    }

    #[test]
    fn builds_role_ownership_transfer_sql() {
        let sql = build_transfer_role_ownership_sql("ANALYST", "SECURITYADMIN");

        assert_eq!(
            sql,
            "GRANT OWNERSHIP ON ROLE \"ANALYST\" TO ROLE \"SECURITYADMIN\" COPY CURRENT GRANTS;"
        );
    }
}
