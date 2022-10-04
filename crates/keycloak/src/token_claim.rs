use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenClaim {
    pub iat: u64,
    pub exp: u64,
    pub azp: String,
    pub given_name: String,
    pub family_name: String,
    pub email: String,
}
