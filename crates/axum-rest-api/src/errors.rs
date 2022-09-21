use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

pub type AxResult<T: IntoAxResponse> = Result<T, AxError>;

#[derive(Clone, Serialize, Debug, Default)]
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

#[derive(Debug, Serialize, Clone, Default)]
pub struct ApiResponse {
    pub status: ResponseStatus,
    pub message: String,
}

impl ApiResponse {
    pub fn new(message: String) -> Self {
        Self {
            status: ResponseStatus::ERROR,
            message,
        }
    }
}

impl IntoResponse for AxError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Self::InternalServerErrorWithContext(err) => (StatusCode::INTERNAL_SERVER_ERROR, err),
            Self::NotFound(err) => (StatusCode::NOT_FOUND, err),
            Self::ObjectConflict(err) => (StatusCode::CONFLICT, err),
            Self::InvalidLoginAttmpt => (
                StatusCode::BAD_REQUEST,
                Self::InvalidLoginAttmpt.to_string(),
            ),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, Self::Unauthorized.to_string()),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("unexpected error occurred"),
            ),
        };

        let body = Json(ApiResponse::new(error_message));

        (status, body).into_response()
    }
}
