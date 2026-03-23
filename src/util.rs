use std::collections::BTreeSet;

use indexmap::{IndexMap, IndexSet};

use crate::resource::{ObjectType, SnowflakeRole, SnowflakeUser};

pub mod api;
pub mod record;
pub mod sql;

pub fn flatten_grants(grants: &IndexMap<String, Vec<ObjectType>>) -> BTreeSet<(String, ObjectType)> {
    grants
        .iter()
        .flat_map(|(privilege, object_types)| {
            object_types
                .iter()
                .cloned()
                .map(|object_type| (privilege.clone(), object_type))
                .collect::<Vec<_>>()
        })
        .collect()
}

pub fn user_properties_only(user: &SnowflakeUser) -> SnowflakeUser {
    SnowflakeUser {
        granted_roles: IndexSet::new(),
        grants: IndexMap::new(),
        ..user.clone()
    }
}

pub fn role_properties_only(role: &SnowflakeRole) -> SnowflakeRole {
    SnowflakeRole {
        owner: None,
        granted_roles: IndexSet::new(),
        grants: IndexMap::new(),
        future_grants: IndexMap::new(),
        ..role.clone()
    }
}

pub fn describe_object_type(object_type: &ObjectType, future: bool) -> String {
    let (kind, name) = match object_type {
        ObjectType::ACCOUNT(_) => ("ACCOUNT", ""),
        ObjectType::CATALOG_INTEGRATION(name) => ("CATALOG INTEGRATION", name.as_str()),
        ObjectType::COMPUTE_POOL(name) => ("COMPUTE POOL", name.as_str()),
        ObjectType::DATABASE(name) => ("DATABASE", name.as_str()),
        ObjectType::DATABASE_ROLE(name) => ("DATABASE ROLE", name.as_str()),
        ObjectType::DYNAMIC_TABLE(name) => ("DYNAMIC TABLE", name.as_str()),
        ObjectType::EVENT_TABLE(name) => ("EVENT TABLE", name.as_str()),
        ObjectType::EXTERNAL_VOLUME(name) => ("EXTERNAL VOLUME", name.as_str()),
        ObjectType::FUNCTION(name) => ("FUNCTION", name.as_str()),
        ObjectType::IMAGE_REPOSITORY(name) => ("IMAGE REPOSITORY", name.as_str()),
        ObjectType::MANAGED_ACCOUNT(name) => ("MANAGED ACCOUNT", name.as_str()),
        ObjectType::NETWORK_POLICY(name) => ("NETWORK POLICY", name.as_str()),
        ObjectType::NOTEBOOK(name) => ("NOTEBOOK", name.as_str()),
        ObjectType::NOTIFICATION_INTEGRATION(name) => ("NOTIFICATION INTEGRATION", name.as_str()),
        ObjectType::PIPE(name) => ("PIPE", name.as_str()),
        ObjectType::PROCEDURE(name) => ("PROCEDURE", name.as_str()),
        ObjectType::ROLE(name) => ("ROLE", name.as_str()),
        ObjectType::SCHEMA(name) => ("SCHEMA", name.as_str()),
        ObjectType::SERVICE(name) => ("SERVICE", name.as_str()),
        ObjectType::STAGE(name) => ("STAGE", name.as_str()),
        ObjectType::STREAM(name) => ("STREAM", name.as_str()),
        ObjectType::TABLE(name) => ("TABLE", name.as_str()),
        ObjectType::TASK(name) => ("TASK", name.as_str()),
        ObjectType::USER_DEFINED_FUNCTION(name) => ("FUNCTION", name.as_str()),
        ObjectType::VIEW(name) => ("VIEW", name.as_str()),
        ObjectType::WAREHOUSE(name) => ("WAREHOUSE", name.as_str()),
    };

    if name.is_empty() {
        if future { format!("future {kind}") } else { kind.to_string() }
    } else if future {
        format!("future {kind} `{name}`")
    } else {
        format!("{kind} `{name}`")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flatten_grants_is_order_independent() {
        let mut grants = IndexMap::new();
        grants.insert(
            "USAGE".into(),
            vec![
                ObjectType::SCHEMA("RAW.PUBLIC".into()),
                ObjectType::DATABASE("RAW".into()),
                ObjectType::SCHEMA("RAW.PUBLIC".into()),
            ],
        );
        grants.insert("SELECT".into(), vec![ObjectType::TABLE("RAW.PUBLIC.EVENTS".into())]);

        let flattened = flatten_grants(&grants);

        assert_eq!(flattened.len(), 3);
        assert!(flattened.contains(&("USAGE".into(), ObjectType::DATABASE("RAW".into()))));
        assert!(flattened.contains(&("USAGE".into(), ObjectType::SCHEMA("RAW.PUBLIC".into()))));
        assert!(flattened.contains(&("SELECT".into(), ObjectType::TABLE("RAW.PUBLIC.EVENTS".into()))));
    }
}
