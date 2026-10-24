use thiserror::Error;

pub type ContractResult<T> = Result<T, ContractError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContractError {
    #[error("{code}: {message}")]
    Invalid { code: &'static str, message: String },
}

impl ContractError {
    pub fn invalid(code: &'static str, message: impl Into<String>) -> Self {
        Self::Invalid {
            code,
            message: message.into(),
        }
    }
}
