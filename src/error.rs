use chrono::ParseError;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]

pub enum CdxVexError {
    #[error("Fail to read file")]
    IoError(#[from] std::io::Error),
    // #[error("failed to read {path}")]
    // ReadFile {
    //     path: PathBuf,
    //     #[source]
    //     source: std::io::Error,
    // },
    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("parse error: {0}")]
    ParseError(#[from] ParseError),

    #[error("Filter format must be of format \"cYYYY-MM-DD\" where c is =, <, or >: {0}")]
    InvalidLastUpdatedFilter(String),
}
