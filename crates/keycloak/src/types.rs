use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub enum GrantType {
    #[serde(rename = "password")]
    PASSWORD,
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
    #[serde(rename = "client_credentials")]
    ClientCredentials,
    #[serde(rename = "refresh_token")]
    RefreshToken,
}

impl Default for GrantType {
    fn default() -> Self {
        GrantType::PASSWORD
    }
}

#[derive(Debug, Serialize, Default)]
pub struct TokenRequest {
    pub username: Option<String>,
    pub password: Option<String>,
    pub refresh_token: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub grant_type: GrantType,
}

impl TokenRequest {
    pub fn username_password(username: String, password: String) -> Self {
        Self {
            username: Some(username),
            password: Some(password),
            ..Default::default()
        }
    }

    pub fn refresh_token(refresh_token: String) -> Self {
        Self {
            refresh_token: Some(refresh_token),
            grant_type: GrantType::RefreshToken,
            ..Default::default()
        }
    }

    pub fn client() -> Self {
        Self {
            grant_type: GrantType::ClientCredentials,
            ..Default::default()
        }
    }

    pub fn client_id(mut self, client_id: &str) -> Self {
        self.client_id = client_id.to_owned();
        self
    }

    pub fn client_secret(mut self, client_secret: &str) -> Self {
        self.client_secret = client_secret.to_owned();
        self
    }
}

#[derive(Debug, Serialize)]
pub struct TokenVerifyRequest {
    pub token: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Serialize, Default)]
struct Credentials {
    #[serde(rename = "type")]
    creadential_type: String,
    value: String,
    temporary: bool,
}

#[derive(Debug, Serialize, Default)]
pub struct CreateUserRequest {
    #[serde(rename = "firstName")]
    firstname: String,
    #[serde(rename = "lastName")]
    lastname: String,
    username: String,
    email: String,
    attributes: HashMap<String, String>,
    enabled: bool,
    credentials: Vec<Credentials>,
}

impl CreateUserRequest {
    pub fn new(
        firstname: String,
        lastname: String,
        username: String,
        email: String,
        password: String,
    ) -> Self {
        Self {
            firstname,
            lastname,
            username,
            email,
            enabled: true,
            attributes: HashMap::new(),
            credentials: vec![Credentials {
                creadential_type: "password".to_owned(),
                value: password,
                temporary: false,
            }],
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub refresh_expires_in: u64,
    pub token_type: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenVerifyResponse {
    pub active: bool,
}
