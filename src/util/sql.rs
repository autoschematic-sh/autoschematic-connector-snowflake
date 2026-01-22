use crate::resource::{SnowflakeRole, SnowflakeUser};

pub fn build_create_role_sql(name: &str, role: &SnowflakeRole) -> String {
    let mut sql = format!("CREATE ROLE \"{}\"", name);

    if let Some(ref comment) = role.comment {
        sql.push_str(&format!(" COMMENT = '{}'", comment.replace('\'', "''")));
    }

    sql.push(';');
    sql
}

pub fn build_alter_role_sql(name: &str, role: &SnowflakeRole) -> String {
    if let Some(ref comment) = role.comment {
        format!("ALTER ROLE \"{}\" SET COMMENT = '{}';", name, comment.replace('\'', "''"))
    } else {
        format!("ALTER ROLE \"{}\" UNSET COMMENT;", name)
    }
}

pub fn build_create_user_sql(name: &str, user: &SnowflakeUser) -> String {
    let mut sql = format!("CREATE USER \"{}\"", name);
    let mut props = Vec::new();

    if let Some(ref login_name) = user.login_name {
        props.push(format!("LOGIN_NAME = '{}'", login_name));
    }
    if let Some(ref display_name) = user.display_name {
        props.push(format!("DISPLAY_NAME = '{}'", display_name));
    }
    if let Some(ref first_name) = user.first_name {
        props.push(format!("FIRST_NAME = '{}'", first_name));
    }
    if let Some(ref last_name) = user.last_name {
        props.push(format!("LAST_NAME = '{}'", last_name));
    }
    if let Some(ref email) = user.email {
        props.push(format!("EMAIL = '{}'", email));
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
            props.push(format!("DEFAULT_SECONDARY_ROLES = ('{}')", default_secondary_roles));
        } else {
            props.push(format!("DEFAULT_SECONDARY_ROLES = ({})", default_secondary_roles));
        }
    }
    if user.disabled {
        props.push("DISABLED = TRUE".to_string());
    }
    if let Some(ref rsa_public_key) = user.rsa_public_key {
        props.push(format!("RSA_PUBLIC_KEY = '{}'", rsa_public_key));
    }
    if let Some(ref rsa_public_key_2) = user.rsa_public_key_2 {
        props.push(format!("RSA_PUBLIC_KEY_2 = '{}'", rsa_public_key_2));
    }
    if let Some(ref comment) = user.comment {
        props.push(format!("COMMENT = '{}'", comment.replace('\'', "''")));
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
    let mut sql = format!("ALTER USER \"{}\" SET", name);
    let mut props = Vec::new();

    // For ALTER USER, we need to set all properties to their desired values
    if let Some(ref login_name) = user.login_name {
        props.push(format!("LOGIN_NAME = '{}'", login_name));
    }
    if let Some(ref display_name) = user.display_name {
        props.push(format!("DISPLAY_NAME = '{}'", display_name));
    }
    if let Some(ref first_name) = user.first_name {
        props.push(format!("FIRST_NAME = '{}'", first_name));
    }
    if let Some(ref last_name) = user.last_name {
        props.push(format!("LAST_NAME = '{}'", last_name));
    }
    if let Some(ref email) = user.email {
        props.push(format!("EMAIL = '{}'", email));
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
            props.push(format!("DEFAULT_SECONDARY_ROLES = ('{}')", default_secondary_roles));
        } else {
            props.push(format!("DEFAULT_SECONDARY_ROLES = ({})", default_secondary_roles));
        }
    }

    props.push(format!("DISABLED = {}", if user.disabled { "TRUE" } else { "FALSE" }));

    if let Some(ref rsa_public_key) = user.rsa_public_key {
        props.push(format!("RSA_PUBLIC_KEY = '{}'", rsa_public_key));
    }
    if let Some(ref rsa_public_key_2) = user.rsa_public_key_2 {
        props.push(format!("RSA_PUBLIC_KEY_2 = '{}'", rsa_public_key_2));
    }
    if let Some(ref comment) = user.comment {
        props.push(format!("COMMENT = '{}'", comment.replace('\'', "''")));
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
