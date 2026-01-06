use autoschematic_core::tarpc_bridge::tarpc_connector_main;
use connector::SnowflakeConnector;

pub mod addr;
pub mod connector;
pub mod error;
pub mod op;
pub mod resource;
pub mod util;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tarpc_connector_main::<SnowflakeConnector>().await?;
    Ok(())
}
