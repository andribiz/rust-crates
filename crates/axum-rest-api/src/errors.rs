use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

pub type AxResult<T> = Result<AxResponse<T>, AxError>;

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub enum ResponseStatus {
    #[default]
    OK,
    ERROR,
}

#[derive(Error, Debug)]
pub enum AxError {
    #[error("authentication is required to access this resource")]
    Unauthorized,
    #[error("username or password is incorrect")]
    InvalidLoginAttmpt,
    #[error("user does not have privilege to access this resource")]
    Forbidden,
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    ApplicationStartup(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("unexpected error has occurred")]
    InternalServerError,
    #[error("{0}")]
    InternalServerErrorWithContext(String),
    #[error("{0}")]
    ObjectConflict(String),
    #[error(transparent)]
    AxumJsonRejection(#[from] axum::extract::rejection::JsonRejection),
    #[error(transparent)]
    AnyhowError(#[from] anyhow::Error),
}

impl IntoResponse for AxError {
    fn into_response(self) -> Response {
        error!("Error Response: {}", self);
        let (status, error_message) = match self {
            Self::InternalServerErrorWithContext(err) => (StatusCode::INTERNAL_SERVER_ERROR, err),
            Self::NotFound(err) => (StatusCode::NOT_FOUND, err),
            Self::ObjectConflict(err) => (StatusCode::CONFLICT, err),
            Self::InvalidLoginAttmpt => (
                StatusCode::BAD_REQUEST,
                Self::InvalidLoginAttmpt.to_string(),
            ),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, Self::Unauthorized.to_string()),
            Self::BadRequest(err) => (StatusCode::BAD_REQUEST, err),
            Self::Forbidden => (StatusCode::FORBIDDEN, Self::Forbidden.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        // let body = Json(ApiResponse::new(error_message));
        let body = AxResponse::err(error_message);

        (status, body).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AxResponse<T: Serialize> {
    pub status: ResponseStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<T>,
}

impl<T: Serialize> AxResponse<T> {
    pub fn err(data: T) -> Self {
        Self {
            status: ResponseStatus::ERROR,
            error_message: Some(data),
            result: None,
        }
    }
    pub fn new(data: T) -> Self {
        Self {
            status: ResponseStatus::OK,
            result: Some(data),
            error_message: None,
        }
    }
}

impl<T: Serialize> IntoResponse for AxResponse<T> {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}
