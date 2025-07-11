use autoschematic_core::tarpc_bridge::tarpc_connector_main;
use connector::SnowflakeConnector;

pub mod connector;


#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tarpc_connector_main::<SnowflakeConnector>().await?;
    Ok(())
}
