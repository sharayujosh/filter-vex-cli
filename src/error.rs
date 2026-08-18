use thiserror::Error;

#[derive(Error, Debug)]

pub enum CdxVexError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Filter format must be of format \"cYYYY-MM-DD\" where c is =, <, or >: {0}")]
    InvalidLastUpdatedFilter(String),
}
