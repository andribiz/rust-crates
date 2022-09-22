pub mod error;
mod keycloak;
use std::sync::Arc;

pub use keycloak::Keycloak;
pub mod types;

pub type KeycloakClient = Arc<Keycloak>;
