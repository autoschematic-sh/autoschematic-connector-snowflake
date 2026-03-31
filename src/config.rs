use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Error, bail};
use base64::prelude::*;
use indexmap::IndexMap;
use serde::Deserialize;

use crate::connector::{SnowflakeConnectorAuth, SnowflakeConnectorConfig};

#[derive(Clone, Debug, Default, Deserialize)]
struct SnowflakeCliConnection {
    account: Option<String>,
    user: Option<String>,
    password: Option<String>,
    role: Option<String>,
    warehouse: Option<String>,
    authenticator: Option<String>,
    #[serde(default, alias = "private_key", alias = "private_key_raw")]
    private_key_raw: Option<String>,
    #[serde(default, alias = "private_key_path", alias = "private_key_file")]
    private_key_file: Option<String>,
    #[serde(default, alias = "private_key_passphrase", alias = "private_key_file_pwd")]
    private_key_file_pwd: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SnowflakeCliConfigToml {
    default_connection_name: Option<String>,
    #[serde(default)]
    connections: IndexMap<String, SnowflakeCliConnection>,
}

#[derive(Debug, Default, Deserialize)]
struct SnowflakeCliConnectionsToml {
    #[serde(flatten)]
    connections: IndexMap<String, SnowflakeCliConnection>,
}

fn normalize_env_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn clean_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_string();
        if value.is_empty() { None } else { Some(value) }
    })
}

fn env_var(key: &str) -> Option<String> {
    clean_string(env::var(key).ok())
}

fn resolve_snowflake_config_dir() -> Option<PathBuf> {
    if let Some(path) = env_var("SNOWFLAKE_HOME") {
        return Some(PathBuf::from(path));
    }

    if let Some(home) = dirs::home_dir() {
        let dot_snowflake = home.join(".snowflake");
        if dot_snowflake.exists() {
            return Some(dot_snowflake);
        }
    }

    dirs::config_local_dir().map(|p| p.join("snowflake"))
}

fn resolve_default_connection_name(
    env_default_connection_name: Option<String>,
    config_default_connection_name: Option<String>,
    connections: &IndexMap<String, SnowflakeCliConnection>,
) -> anyhow::Result<String> {
    if let Some(name) = clean_string(env_default_connection_name) {
        return Ok(name);
    }

    if let Some(name) = clean_string(config_default_connection_name) {
        return Ok(name);
    }

    if connections.contains_key("default") {
        return Ok("default".to_string());
    }

    bail!(
        "No default Snowflake connection is configured. Set SNOWFLAKE_DEFAULT_CONNECTION_NAME, \
         set default_connection_name in config.toml, or add a [default] connection."
    )
}

fn apply_connection_env_overrides<F>(
    connection_name: &str,
    connection: &SnowflakeCliConnection,
    get_env: F,
) -> SnowflakeCliConnection
where
    F: Fn(&str) -> Option<String>,
{
    let connection_prefix = format!("SNOWFLAKE_CONNECTIONS_{}_", normalize_env_segment(connection_name));
    let scoped = |suffix: &str| get_env(&format!("{connection_prefix}{suffix}"));
    let generic = |suffix: &str| get_env(&format!("SNOWFLAKE_{suffix}"));
    let prefer = |scoped_value: Option<String>, file_value: &Option<String>, generic_value: Option<String>| {
        clean_string(scoped_value)
            .or_else(|| clean_string(file_value.clone()))
            .or_else(|| clean_string(generic_value))
    };

    SnowflakeCliConnection {
        account: prefer(scoped("ACCOUNT"), &connection.account, generic("ACCOUNT")),
        user: prefer(scoped("USER"), &connection.user, generic("USER")),
        password: prefer(scoped("PASSWORD"), &connection.password, generic("PASSWORD")),
        role: prefer(scoped("ROLE"), &connection.role, generic("ROLE")),
        warehouse: prefer(scoped("WAREHOUSE"), &connection.warehouse, generic("WAREHOUSE")),
        authenticator: prefer(scoped("AUTHENTICATOR"), &connection.authenticator, generic("AUTHENTICATOR")),
        private_key_raw: clean_string(scoped("PRIVATE_KEY_RAW"))
            .or_else(|| clean_string(scoped("PRIVATE_KEY")))
            .or_else(|| clean_string(connection.private_key_raw.clone()))
            .or_else(|| clean_string(generic("PRIVATE_KEY_RAW")))
            .or_else(|| clean_string(generic("PRIVATE_KEY"))),
        private_key_file: clean_string(scoped("PRIVATE_KEY_FILE"))
            .or_else(|| clean_string(scoped("PRIVATE_KEY_PATH")))
            .or_else(|| clean_string(connection.private_key_file.clone()))
            .or_else(|| clean_string(generic("PRIVATE_KEY_FILE")))
            .or_else(|| clean_string(generic("PRIVATE_KEY_PATH"))),
        private_key_file_pwd: prefer(
            scoped("PRIVATE_KEY_FILE_PWD"),
            &connection.private_key_file_pwd,
            generic("PRIVATE_KEY_FILE_PWD"),
        ),
    }
}

fn expand_home_path(path: &str) -> Option<PathBuf> {
    if path == "~" {
        return dirs::home_dir();
    }

    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        return Some(dirs::home_dir()?.join(rest));
    }

    Some(PathBuf::from(path))
}

fn load_private_key(path: &str, config_dir: &Path) -> anyhow::Result<String> {
    let Some(path) = expand_home_path(path) else {
        bail!("Couldn't resolve home dir when loading Snowflake private key");
    };

    let path = if path.is_absolute() { path } else { config_dir.join(path) };

    let pk = fs::read_to_string(&path)?;

    Ok(pk)
}

fn validate_authenticator(authenticator: Option<&str>, auth_kind: &str) -> anyhow::Result<()> {
    let Some(authenticator) = authenticator else {
        return Ok(());
    };

    let normalized = authenticator.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(());
    }

    let supported = match auth_kind {
        "password" => normalized == "snowflake",
        "private_key" => normalized == "snowflake" || normalized == "snowflake_jwt",
        _ => false,
    };

    if supported {
        return Ok(());
    }

    bail!(
        "Unsupported Snowflake authenticator `{authenticator}`. This connector currently supports password auth and key pair auth."
    )
}

fn build_connector_config(
    connection_name: &str,
    connection: SnowflakeCliConnection,
    config_dir: &Path,
) -> anyhow::Result<SnowflakeConnectorConfig> {
    let SnowflakeCliConnection {
        account,
        user,
        password,
        role,
        warehouse,
        authenticator,
        private_key_raw,
        private_key_file,
        private_key_file_pwd,
    } = connection;

    let account = account.context(format!("Snowflake connection `{connection_name}` is missing `account`"))?;
    let user = user.context(format!("Snowflake connection `{connection_name}` is missing `user`"))?;

    if private_key_file_pwd.is_some() {
        bail!(
            "Snowflake connection `{connection_name}` uses an encrypted private key, which this connector does not support yet."
        );
    }

    let auth = match (password, private_key_raw, private_key_file) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) | (None, Some(_), Some(_)) => {
            bail!(
                "Snowflake connection `{connection_name}` has ambiguous authentication settings. \
                 Configure exactly one of `password`, `private_key_raw`/`private_key`, or `private_key_file`/`private_key_path`."
            );
        }
        (Some(password), None, None) => {
            validate_authenticator(authenticator.as_deref(), "password")?;
            SnowflakeConnectorAuth::Password(password)
        }
        (None, Some(private_key), None) => {
            validate_authenticator(authenticator.as_deref(), "private_key")?;
            SnowflakeConnectorAuth::PrivateKey(private_key)
        }
        (None, None, Some(private_key_file)) => {
            validate_authenticator(authenticator.as_deref(), "private_key")?;
            SnowflakeConnectorAuth::PrivateKey(load_private_key(&private_key_file, config_dir)?)
        }
        (None, None, None) => {
            bail!(
                "Snowflake connection `{connection_name}` is missing authentication. \
                 Configure `password`, `private_key_raw`/`private_key`, or `private_key_file`/`private_key_path`."
            );
        }
    };

    Ok(SnowflakeConnectorConfig {
        account,
        user,
        role: clean_string(role),
        warehouse: clean_string(warehouse),
        auth,
    })
}

pub fn load_snowflake_cli_connector_config() -> anyhow::Result<Option<SnowflakeConnectorConfig>> {
    let Some(config_dir) = resolve_snowflake_config_dir() else {
        bail!("Couldn't resolve Snowflake config directory");
    };
    let config_path = config_dir.join("config.toml");
    let connections_path = config_dir.join("connections.toml");

    let config_file = if config_path.is_file() {
        let contents = fs::read_to_string(&config_path).with_context(|| format!("Failed to read {}", config_path.display()))?;
        Some(
            toml::from_str::<SnowflakeCliConfigToml>(&contents)
                .with_context(|| format!("Failed to parse Snowflake CLI config at {}", config_path.display()))?,
        )
    } else {
        None
    };

    let connections = if connections_path.is_file() {
        let contents =
            fs::read_to_string(&connections_path).with_context(|| format!("Failed to read {}", connections_path.display()))?;
        toml::from_str::<SnowflakeCliConnectionsToml>(&contents)
            .with_context(|| format!("Failed to parse Snowflake CLI connections at {}", connections_path.display()))?
            .connections
    } else if let Some(config_file) = &config_file {
        config_file.connections.clone()
    } else {
        return Ok(None);
    };

    if connections.is_empty() {
        return Ok(None);
    }

    let connection_name = resolve_default_connection_name(
        env_var("SNOWFLAKE_DEFAULT_CONNECTION_NAME"),
        config_file.as_ref().and_then(|config| config.default_connection_name.clone()),
        &connections,
    )?;

    let connection = connections.get(&connection_name).with_context(|| {
        format!(
            "Snowflake connection `{connection_name}` was selected as the default, but it was not found in {}",
            if connections_path.is_file() {
                connections_path.display().to_string()
            } else {
                config_path.display().to_string()
            }
        )
    })?;

    let connection = apply_connection_env_overrides(&connection_name, connection, env_var);
    build_connector_config(&connection_name, connection, &config_dir).map(Some)
}

pub fn load_legacy_env_connector_config() -> anyhow::Result<SnowflakeConnectorConfig> {
    let account = env::var("SF_ACCOUNT").context("SF_ACCOUNT env var not set!")?;
    let user = env::var("SF_USER").context("SF_USER env var not set!")?;
    let role = env::var("SF_ROLE").ok();
    let warehouse = env::var("SF_WAREHOUSE").ok();
    let private_key_base64 = env::var("SF_PRIVATE_KEY_BASE64");
    let private_key_path = env::var("SF_PRIVATE_KEY_PATH");

    let private_key = match (private_key_base64, private_key_path) {
        (Ok(_), Ok(_)) => Err(Error::msg(
            "Ambiguous: Only one of SF_PRIVATE_KEY_BASE64 and SF_PRIVATE_KEY_PATH can be set!",
        )),
        (Ok(private_key_base64), Err(_)) => {
            let private_key = BASE64_STANDARD
                .decode(private_key_base64)
                .context("Failed to decode SF_PRIVATE_KEY_BASE64")?;
            Ok(String::from_utf8(private_key).context("SF_PRIVATE_KEY_BASE64 is not valid UTF-8")?)
        }
        (Err(_), Ok(private_key_path)) => fs::read_to_string(&private_key_path)
            .with_context(|| format!("Failed to read private key from {}", private_key_path)),
        (Err(_), Err(_)) => Err(Error::msg("SF_PRIVATE_KEY_BASE64 or SF_PRIVATE_KEY_PATH not set!")),
    }?;

    Ok(SnowflakeConnectorConfig {
        account,
        user,
        role: clean_string(role),
        warehouse: clean_string(warehouse),
        auth: SnowflakeConnectorAuth::PrivateKey(private_key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs, sync::Mutex};
    use uuid::Uuid;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct TestEnv {
        root: PathBuf,
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl TestEnv {
        fn new() -> Self {
            let root = env::temp_dir().join(format!("autoschematic-snowflake-test-{}", Uuid::new_v4()));
            fs::create_dir_all(&root).unwrap();

            Self { root, saved: Vec::new() }
        }

        fn root(&self) -> &Path {
            &self.root
        }

        fn save_var(&mut self, key: &'static str) {
            if self.saved.iter().any(|(saved_key, _)| *saved_key == key) {
                return;
            }

            self.saved.push((key, env::var(key).ok()));
        }

        fn set_var(&mut self, key: &'static str, value: &str) {
            self.save_var(key);
            unsafe {
                env::set_var(key, value);
            }
        }

        fn remove_var(&mut self, key: &'static str) {
            self.save_var(key);
            unsafe {
                env::remove_var(key);
            }
        }

        fn write(&self, relative_path: &str, contents: &str) {
            let path = self.root.join(relative_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, contents).unwrap();
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..).rev() {
                unsafe {
                    match value {
                        Some(value) => env::set_var(key, value),
                        None => env::remove_var(key),
                    }
                }
            }

            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn loads_default_connection_from_connections_toml_using_config_default_name() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut test_env = TestEnv::new();
        let snowflake_home = test_env.root().to_str().unwrap().to_string();

        test_env.set_var("SNOWFLAKE_HOME", &snowflake_home);
        test_env.remove_var("SNOWFLAKE_DEFAULT_CONNECTION_NAME");

        test_env.write(
            "config.toml",
            r#"
default_connection_name = "prod"

[connections.ignored]
account = "ignored-account"
user = "ignored-user"
password = "ignored-password"
"#,
        );

        test_env.write(
            "connections.toml",
            r#"
[prod]
account = "prod-account"
user = "prod-user"
password = "prod-password"
role = "SECURITYADMIN"
warehouse = "COMPUTE_WH"
"#,
        );

        let config = load_snowflake_cli_connector_config().unwrap().unwrap();

        assert_eq!(config.account, "prod-account");
        assert_eq!(config.user, "prod-user");
        assert_eq!(config.role.as_deref(), Some("SECURITYADMIN"));
        assert_eq!(config.warehouse.as_deref(), Some("COMPUTE_WH"));
        match config.auth {
            SnowflakeConnectorAuth::Password(password) => assert_eq!(password, "prod-password"),
            SnowflakeConnectorAuth::PrivateKey(_) => panic!("expected password auth"),
        }
    }

    #[test]
    fn scoped_env_overrides_beat_file_values_and_generic_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut test_env = TestEnv::new();
        let snowflake_home = test_env.root().to_str().unwrap().to_string();

        test_env.set_var("SNOWFLAKE_HOME", &snowflake_home);
        test_env.remove_var("SNOWFLAKE_DEFAULT_CONNECTION_NAME");
        test_env.set_var("SNOWFLAKE_CONNECTIONS_DEFAULT_USER", "scoped-user");
        test_env.set_var("SNOWFLAKE_PASSWORD", "generic-password");

        test_env.write(
            "connections.toml",
            r#"
[default]
account = "default-account"
user = "file-user"
password = "file-password"
"#,
        );

        let config = load_snowflake_cli_connector_config().unwrap().unwrap();

        assert_eq!(config.account, "default-account");
        assert_eq!(config.user, "scoped-user");
        match config.auth {
            SnowflakeConnectorAuth::Password(password) => assert_eq!(password, "file-password"),
            SnowflakeConnectorAuth::PrivateKey(_) => panic!("expected password auth"),
        }
    }

    #[test]
    fn relative_private_key_paths_are_resolved_from_snowflake_config_dir() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut test_env = TestEnv::new();
        let snowflake_home = test_env.root().to_str().unwrap().to_string();

        test_env.set_var("SNOWFLAKE_HOME", &snowflake_home);
        test_env.remove_var("SNOWFLAKE_DEFAULT_CONNECTION_NAME");
        test_env.write("keys/test_key.pem", "PRIVATE KEY");
        test_env.write(
            "connections.toml",
            r#"
[default]
account = "default-account"
user = "default-user"
private_key_file = "keys/test_key.pem"
"#,
        );

        let config = load_snowflake_cli_connector_config().unwrap().unwrap();

        match config.auth {
            SnowflakeConnectorAuth::PrivateKey(private_key) => assert_eq!(private_key, "PRIVATE KEY"),
            SnowflakeConnectorAuth::Password(_) => panic!("expected private key auth"),
        }
    }
}
