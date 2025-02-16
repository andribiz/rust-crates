use super::error::KeycloakError;
use super::types::*;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::{header::CONTENT_TYPE, Client, StatusCode};
use serde::{de::DeserializeOwned, Deserialize};
use std::{collections::HashMap, env, sync::RwLock};

#[derive(Debug, Deserialize)]
struct CertKey {
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct Keys {
    keys: Vec<CertKey>,
}

#[derive(Debug)]
pub struct Keycloak {
    client_id: String,
    client_secret: String,
    endpoint: String,
    admin_url: String,
    cert_keys: RwLock<Option<HashMap<String, CertKey>>>,
    token: RwLock<Option<TokenResponse>>,
}

impl Keycloak {
    pub fn new(client_id: String, client_secret: String, realm: String, url: String) -> Self {
        Self {
            client_id,
            client_secret,
            endpoint: format!("{}/realms/{}/protocol/openid-connect", url, realm),
            admin_url: format!("{}/admin/realms/{}", url, realm),
            cert_keys: RwLock::new(None),
            token: RwLock::new(None),
        }
    }

    pub fn new_from_env() -> Result<Keycloak, KeycloakError> {
        let client_id = match env::var("KEYCLOAK_CLIENT_ID") {
            Ok(client_id) => client_id,
            Err(_) => {
                return Err(KeycloakError::ConfigNotFound(
                    "KEYCLOAK_CLIENT_ID".to_owned(),
                ))
            }
        };
        let client_secret = match env::var("KEYCLOAK_CLIENT_SECRET") {
            Ok(client_secret) => client_secret,
            Err(_) => {
                return Err(KeycloakError::ConfigNotFound(
                    "KEYCLOAK_CLIENT_SECRET".to_owned(),
                ))
            }
        };
        let realm = match env::var("KEYCLOAK_REALM") {
            Ok(realm) => realm,
            Err(_) => return Err(KeycloakError::ConfigNotFound("KEYCLOAK_REALM".to_owned())),
        };
        let url = match env::var("KEYCLOAK_URL") {
            Ok(url) => url,
            Err(_) => return Err(KeycloakError::ConfigNotFound("KEYCLOAK_URL".to_owned())),
        };

        Ok(Self {
            client_id,
            client_secret,
            endpoint: format!("{}/realms/{}/protocol/openid-connect", url, realm),
            admin_url: format!("{}/admin/realms/{}", url, realm),
            cert_keys: RwLock::new(None),
            token: RwLock::new(None),
        })
    }

    // TODO: Using this to optimize performance of client SC token
    // pub async fn init(&mut self) -> Result<(), KeycloakError> {
    //     self.load_keys().await?;
    //     self.load_client_token().await?;
    //     Ok(())
    // }

    pub async fn load_client_token(&self) -> Result<(), KeycloakError> {
        let req = TokenRequest::client();
        let token = self.get_oauth2_token(req).await?;

        let guard = self.token.write();
        match guard {
            Ok(mut guard) => *guard = Some(token),
            Err(_) => return Err(KeycloakError::WriteLockFailed),
        }
        Ok(())
    }

    pub async fn load_keys(&self) -> Result<(), KeycloakError> {
        let url = format!("{}/certs", self.endpoint);
        let response = Client::new().get(url).send().await?;
        match response.status() {
            StatusCode::OK => {
                let cert_keys = response.json::<Keys>().await?;
                match self.cert_keys.write() {
                    Ok(mut lock) => {
                        *lock = Some(
                            cert_keys
                                .keys
                                .into_iter()
                                .map(|key| (key.kid.clone(), key))
                                .collect(),
                        );
                        Ok(())
                    }
                    Err(_) => Err(KeycloakError::WriteLockFailed),
                }
            }
            _ => Err(KeycloakError::ResponseError(
                response.status(),
                response.text().await?,
            )),
        }
    }

    // pub async fn admin_create_users(
    //     &self,
    //     user: UserRequest,
    // ) -> Result<UserRequest, KeycloakError> {
    //     Ok(())
    // }

    pub async fn get_sc_oauth2_token(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TokenResponse, KeycloakError> {
        let request = TokenRequest::client()
            .client_id(client_id)
            .client_secret(client_secret);
        let data = serde_urlencoded::to_string(request)?;
        let url = format!("{}/token", self.endpoint);
        let response = Client::new()
            .post(url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(data)
            .send()
            .await?;
        match response.status() {
            StatusCode::OK => Ok(response.json::<TokenResponse>().await?),
            StatusCode::UNAUTHORIZED => Err(KeycloakError::UnAuthorized),
            _ => Err(KeycloakError::ResponseError(
                response.status(),
                response.text().await?,
            )),
        }
    }

    pub async fn get_oauth2_token(
        &self,
        request: TokenRequest,
    ) -> Result<TokenResponse, KeycloakError> {
        let data = serde_urlencoded::to_string(
            request
                .client_id(&self.client_id)
                .client_secret(&self.client_secret),
        )?;
        let url = format!("{}/token", self.endpoint);
        let response = Client::new()
            .post(url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(data)
            .send()
            .await?;
        match response.status() {
            StatusCode::OK => Ok(response.json::<TokenResponse>().await?),
            StatusCode::UNAUTHORIZED => Err(KeycloakError::UnAuthorized),
            _ => Err(KeycloakError::ResponseError(
                response.status(),
                response.text().await?,
            )),
        }
    }

    pub async fn verify_token(&self, token: String) -> Result<TokenVerifyResponse, KeycloakError> {
        let data = serde_urlencoded::to_string(TokenVerifyRequest {
            token,
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
        })?;
        let url = format!("{}/token/introspect", self.endpoint);
        let response = Client::new()
            .post(url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(data)
            .send()
            .await?;
        match response.status() {
            StatusCode::OK => Ok(response.json::<TokenVerifyResponse>().await?),
            _ => Err(KeycloakError::ResponseError(
                response.status(),
                response.text().await?,
            )),
        }
    }

    pub async fn register_user(&self, user: &CreateUserRequest) -> Result<(), KeycloakError> {
        let token = self.get_oauth2_token(TokenRequest::client()).await?;
        let url = format!("{}/users", self.admin_url);
        let response = Client::new()
            .post(url)
            .bearer_auth(token.access_token)
            .json(&user)
            .send()
            .await?;
        match response.status() {
            StatusCode::CREATED => Ok(()),
            _ => Err(KeycloakError::ResponseError(
                response.status(),
                response.text().await?,
            )),
        }
    }

    pub fn decode<T: DeserializeOwned>(&self, token: String) -> Result<T, KeycloakError> {
        let header = decode_header(&token)?;
        match header.alg {
            Algorithm::RS256 => {
                let kid = match header.kid {
                    Some(kid) => kid,
                    None => return Err(KeycloakError::Other("KID not specified".to_owned())),
                };
                let read = &self.cert_keys.read();
                let (n, e) = match read {
                    Ok(guard) => match &(**guard) {
                        Some(cert_keys) => match cert_keys.get(&kid) {
                            Some(key) => Ok((&key.n, &key.e)),
                            None => Err(KeycloakError::Other("Key id not found".to_owned())),
                        },
                        None => Err(KeycloakError::Other("Cert Key Empty".to_owned())),
                    },
                    Err(_) => Err(KeycloakError::ReadLockFailed),
                }?;
                let token = decode::<T>(
                    &token,
                    &DecodingKey::from_rsa_components(n, e)?,
                    &Validation::new(Algorithm::RS256),
                )?;
                Ok(token.claims)
            }
            _ => Err(KeycloakError::Other("Algorithm Not Supported".to_owned())),
        }
    }

    // pub async fn
}

#[cfg(test)]
mod tests {
    use crate::keycloak::types::CreateUserRequest;
    use crate::keycloak::types::TokenRequest;
    use crate::TokenClaim;

    use super::KeycloakError;

    use super::Keycloak;
    use anyhow::Result;

    const EXPIRED_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHc205MTFLTTR3YmV4Y2VjTGhrYnp5MnlvdkVIblIyV0pmMTNLekNKbkdVIn0.eyJleHAiOjE2NTU3NDY2NjEsImlhdCI6MTY1NTc0NjM2MSwianRpIjoiODgwZDJkMzUtYjQ0My00YjkyLWEwZjctYmQ2MzhjYWQ4N2Y5IiwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS5iaXpvZnQuaWQvYXV0aC9yZWFsbXMvY3J5cHRvLXRpcHBpbmciLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiYTk5YTIzZDgtYzc1ZS00YTE5LWFkZWMtMmMyNmMyNmE3NGNkIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYmFja2VuZC1zZXJ2aWNlIiwic2Vzc2lvbl9zdGF0ZSI6IjE2YTc3NzZmLTk5MmQtNGIzOC1iZmJlLTVlYmNlYmZkNWRjMyIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiQW5kcmlhbnRvIEt1cm5pYXdhbiIsInByZWZlcnJlZF91c2VybmFtZSI6ImFuZHJpeDIxQGdtYWlsLmNvbSIsImdpdmVuX25hbWUiOiJBbmRyaWFudG8iLCJmYW1pbHlfbmFtZSI6Ikt1cm5pYXdhbiIsImVtYWlsIjoiYW5kcml4MjFAZ21haWwuY29tIn0.VzHzC9h377p4EZALKzw6Evi0iv2IEagBj2hFdjvO8I5GvcibNe1YGvE8EZVhC-U9MU2XGUFYCI4Bm5MKS-xarHdpHKb52xWYUqle9L1JLhr6tJ2tZoCoyQRNQrdBKA9zkQ5_ajiH-HOdxGzms-79-z-NotvkNk0BClYsAhQ90q-8C-r9uBZQgwO_rpER9CvsATvWi897lObH0ZNAT-NkfxcITa3ZCzjkzjqiZazl5VO64Y8-_0Eo1s3ys3oiCGrnQJu4QtsXx8u5NHIEZF_U17X7GUmkvDr8yW1s7nTkiv1Iamt3cU9GBULppZWNltO1XePuB5ggHTmg_PyJy-6_Ow";
    #[tokio::test]
    async fn test_login() -> Result<(), KeycloakError> {
        dotenv().ok();
        let client = Keycloak::new_from_env()?;
        let request = TokenRequest {
            username: Some("andrix21@gmail.com".to_owned()),
            password: Some("saya".to_owned()),
            ..Default::default()
        };
        let res = client.get_oauth2_token(request).await?;
        println!("{:?}", res);
        assert_ne!(res.access_token, "");
        Ok(())
    }

    #[tokio::test]
    async fn test_load_certs() -> Result<(), KeycloakError> {
        dotenv().ok();
        let client = Keycloak::new_from_env()?;
        client.load_keys().await?;
        println!("{:?}", client);
        let x = match client.cert_keys.read() {
            Ok(guard) => {
                assert_eq!((*guard).is_none(), false);
                if let Some(cert_keys) = &(*guard) {
                    assert!(cert_keys.len() > 0);
                }
                Ok(())
            }
            Err(_) => Err(KeycloakError::ReadLockFailed),
        };
        x
    }

    #[tokio::test]
    async fn test_verify() -> Result<(), KeycloakError> {
        dotenv().ok();
        let client = Keycloak::new_from_env()?;
        let res = client.verify_token(EXPIRED_TOKEN.to_owned()).await?;
        println!("{:?}", res);
        assert_eq!(res.active, false);

        let request = TokenRequest {
            username: Some("andrix21@gmail.com".to_owned()),
            password: Some("saya".to_owned()),
            ..Default::default()
        };
        let res2 = client.get_oauth2_token(request).await?;

        let res = client.verify_token(res2.access_token.to_owned()).await?;
        println!("{:?}", res);
        assert_eq!(res.active, true);
        Ok(())
    }

    #[tokio::test]
    async fn test_register_user() -> Result<(), KeycloakError> {
        dotenv().ok();
        let client = Keycloak::new_from_env()?;

        let request = CreateUserRequest::new(
            "First".to_owned(),
            "Second".to_owned(),
            "username".to_owned(),
            "ini@email.com".to_owned(),
            "anjinggalak".to_owned(),
        );
        client.register_user(&request).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_decode() -> Result<(), KeycloakError> {
        dotenv().ok();
        let client = Keycloak::new_from_env()?;
        client.load_keys().await?;

        let request = TokenRequest {
            username: Some("andrix21@gmail.com".to_owned()),
            password: Some("saya".to_owned()),
            ..Default::default()
        };
        let res = client.get_oauth2_token(request).await?;

        let claims = client.decode::<TokenClaim>(res.access_token.to_owned())?;

        println!("{:?}", claims);
        assert_ne!(claims.email, "");
        Ok(())
    }
}
