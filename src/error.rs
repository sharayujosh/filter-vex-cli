use chrono::ParseError;
use thiserror::Error;

#[derive(Error, Debug)]

pub enum CdxVexError {
    #[error("Fail to read file")]
    IoError(#[from] std::io::Error),

    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("parse error: ")]
    ParseError(#[from] ParseError),

    #[error("Filter format must be of format \"cYYYY-MM-DD\" where c is =, <, or >: {0}")]
    InvalidDateFilter(String),
}
