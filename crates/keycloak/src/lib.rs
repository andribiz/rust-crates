pub mod error;
mod keycloak;
use std::sync::Arc;
mod token_claim;
pub use keycloak::Keycloak;
pub use token_claim::TokenClaim;
pub mod types;

pub type KeycloakClient = Arc<Keycloak>;
