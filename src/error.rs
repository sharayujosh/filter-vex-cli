use thiserror::Error;

#[derive(Error, Debug)]

pub enum CdxVexError {
    #[error("Filter format must be of format "%c%YYYY-%MM-%DD" where %c is =, <, or >: {0}")]
    InvalidLastUpdatedFilter(String),
}