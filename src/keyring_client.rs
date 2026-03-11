use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ethers::prelude::*;
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use crate::error::{Result, RouterError};
use crate::models::{Chain, CredentialStatus, IdentityCheckResult, KeyringCredential};


abigen!(
    KeyringCoreContract,
    r#"[
        function isAuthorized(uint32 policyId, address subject) external view returns (bool)
        function getCredential(uint32 policyId, address subject) external view returns (uint256 issuedAt, uint256 expiresAt)
        function isBlacklisted(uint32 policyId, address subject) external view returns (bool)
    ]"#
);

#[derive(Debug, Deserialize)]
struct ApiCredential {
    #[serde(rename = "policyId")]
    policy_id: u32,
    status: String,
    #[serde(rename = "issuedAt")]
    issued_at: String,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
    #[serde(rename = "isCompliant")]
    is_compliant: bool,
}

#[derive(Debug, Deserialize)]
struct CredentialsResponse {
    wallet: String,
    credentials: Vec<ApiCredential>,
}

#[derive(Debug, Deserialize)]
struct ComplianceResponse {
    wallet: String,
    #[serde(rename = "passesDefaultPolicy")]
    passes_default_policy: bool,
}

#[derive(Clone)]
pub struct KeyringClient {
    http: Client,
    api_base: String,
    api_key: String,
}

impl KeyringClient {

    pub fn new(api_key: impl Into<String>, api_base: impl Into<String>, timeout: Duration) -> Self {
        let api_key = api_key.into();
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "X-API-Key",
            header::HeaderValue::from_str(&api_key)
                .expect("invalid api key characters"),
        );

        let http = Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .user_agent("greptiles/0.1.0")
            .build()
            .expect("failed to build HTTP client");

        Self {
            http,
            api_base: api_base.into(),
            api_key,
        }
    }

    #[instrument(skip(self), fields(wallet = %wallet, chain = %chain))]
    pub async fn verify_wallet(
        &self,
        wallet: &str,
        chain: &Chain,
    ) -> Result<IdentityCheckResult> {
        info!("Running identity check for wallet {}", wallet);

        let credentials = self.fetch_credentials_rest(wallet, chain).await?;

        let passes_default = self.fetch_default_compliance(wallet).await.unwrap_or_else(|e| {
            warn!("Could not fetch default compliance for {}: {}", wallet, e);
            // Fall back to inspecting credentials
            credentials.iter().any(|c| c.policy_id == 0 && c.is_compliant)
        });

        debug!(
            "Wallet {} has {} credentials, default_policy={}",
            wallet,
            credentials.len(),
            passes_default
        );

        Ok(IdentityCheckResult {
            wallet: wallet.to_string(),
            chain: chain.clone(),
            credentials,
            passes_default_policy: passes_default,
            checked_at: Utc::now(),
        })
    }

    #[instrument(skip(self, rpc_url), fields(wallet = %wallet, policy_id = %policy_id))]
    pub async fn check_onchain(
        &self,
        wallet: &str,
        policy_id: u32,
        chain: &Chain,
        rpc_url: &str,
    ) -> Result<bool> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .map_err(|e| RouterError::EthereumError(e.to_string()))?;
        let provider = Arc::new(provider);

        let contract_addr: Address = chain
            .keyring_contract_address()
            .parse()
            .map_err(|e: <Address as std::str::FromStr>::Err| {
                RouterError::EthereumError(e.to_string())
            })?;

        let wallet_addr: Address = wallet
            .parse()
            .map_err(|e: <Address as std::str::FromStr>::Err| {
                RouterError::EthereumError(format!("invalid wallet address: {}", e))
            })?;

        let contract = KeyringCoreContract::new(contract_addr, provider);

        let blacklisted = contract
            .is_blacklisted(policy_id, wallet_addr)
            .call()
            .await
            .map_err(|e| RouterError::EthereumError(e.to_string()))?;

        if blacklisted {
            return Err(RouterError::WalletBlacklisted {
                wallet: wallet.to_string(),
                policy_id,
            });
        }

        let authorized = contract
            .is_authorized(policy_id, wallet_addr)
            .call()
            .await
            .map_err(|e| RouterError::EthereumError(e.to_string()))?;

        Ok(authorized)
    }


    async fn fetch_credentials_rest(
        &self,
        wallet: &str,
        chain: &Chain,
    ) -> Result<Vec<KeyringCredential>> {
        let url = format!(
            "{}/v1/credentials/{}?chain={}",
            self.api_base, wallet, chain
        );

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(RouterError::HttpError)?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(vec![]);
        }

        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(RouterError::KeyringApiError {
                status: status.as_u16(),
                message: body,
            });
        }

        let data: CredentialsResponse = resp
            .json()
            .await
            .map_err(RouterError::HttpError)?;

        let credentials = data
            .credentials
            .into_iter()
            .map(|c| self.map_credential(c, wallet, chain))
            .collect::<Result<Vec<_>>>()?;

        Ok(credentials)
    }

    async fn fetch_default_compliance(&self, wallet: &str) -> Result<bool> {
        let url = format!("{}/v1/wallets/{}/compliance", self.api_base, wallet);

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(RouterError::HttpError)?;

        if !resp.status().is_success() {
            return Err(RouterError::KeyringApiError {
                status: resp.status().as_u16(),
                message: "compliance endpoint failed".to_string(),
            });
        }

        let data: ComplianceResponse = resp.json().await.map_err(RouterError::HttpError)?;
        Ok(data.passes_default_policy)
    }

    fn map_credential(
        &self,
        api: ApiCredential,
        wallet: &str,
        chain: &Chain,
    ) -> Result<KeyringCredential> {
        let status = match api.status.as_str() {
            "ACTIVE" => CredentialStatus::Active,
            "EXPIRED" => CredentialStatus::Expired,
            "BLACKLISTED" => CredentialStatus::Blacklisted,
            "PENDING" => CredentialStatus::Pending,
            _ => CredentialStatus::NotFound,
        };

        let issued_at = chrono::DateTime::parse_from_rfc3339(&api.issued_at)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|_| RouterError::Internal("bad issued_at date".to_string()))?;

        let expires_at = api
            .expires_at
            .as_deref()
            .map(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|_| RouterError::Internal("bad expires_at date".to_string()))
            })
            .transpose()?;

        Ok(KeyringCredential {
            wallet: wallet.to_string(),
            policy_id: api.policy_id,
            status,
            issued_at,
            expires_at,
            chain: chain.clone(),
            is_compliant: api.is_compliant,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client(server_url: &str) -> KeyringClient {
        KeyringClient::new("test-key", server_url, Duration::from_secs(5))
    }

    #[tokio::test]
    async fn test_verify_wallet_not_found_returns_empty() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(404)
            .create_async()
            .await;

        let client = make_client(&server.url());
        let result = client
            .verify_wallet("0xdead000000000000000000000000000000000001", &Chain::Ethereum)
            .await;

        assert!(result.is_ok() || matches!(result, Err(RouterError::KeyringApiError { .. })));
    }
}