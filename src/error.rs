use thiserror::Error;

#[derive(Error, Debug)]
pub enum SnowflakeConnectorError {
    #[error("We were expecting a JSON result, but got Arrow")]
    UnexpectedArrowResult,
    #[error("We were expecting a JSON result, but got an empty one")]
    UnexpectedEmptyResult,
}
