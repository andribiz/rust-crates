use thiserror::Error;

// TODO: Using error code in reqwest::error and message

#[derive(Debug, Error)]
pub enum KeycloakError {
    #[error("unauthorized access")]
    UnAuthorized,
    #[error("failed to acquire write lock")]
    WriteLockFailed,
    #[error("failed to acquire read lock")]
    ReadLockFailed,
    #[error("{0} not found")]
    ConfigNotFound(String),
    #[error("response error with status code: {0}")]
    ResponseError(reqwest::StatusCode, String),
    #[error("request error: {0}")]
    RequestError(reqwest::Error),
    #[error("jwt error: {0}")]
    JWTError(jsonwebtoken::errors::Error),
    #[error("serde error: {0}")]
    SerdeError(serde_urlencoded::ser::Error),
    #[error("error: {0}")]
    Other(String),
}

impl From<reqwest::Error> for KeycloakError {
    fn from(value: reqwest::Error) -> Self {
        KeycloakError::RequestError(value)
    }
}

impl From<serde_urlencoded::ser::Error> for KeycloakError {
    fn from(value: serde_urlencoded::ser::Error) -> Self {
        KeycloakError::SerdeError(value)
    }
}

impl From<jsonwebtoken::errors::Error> for KeycloakError {
    fn from(value: jsonwebtoken::errors::Error) -> Self {
        KeycloakError::JWTError(value)
    }
}
