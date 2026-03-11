use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Ethereum,
    Arbitrum,
    Optimism,
    Base,
    Avalanche,
    Polygon,
}

impl Chain {

    pub fn keyring_contract_address(&self) -> &'static str {
        match self {
            Chain::Ethereum => "0xb0B5E2176E10B12d70e60E3a68738298A7DFe666",
            Chain::Arbitrum => "0xf26b0F10691ED160734a3A5caf8cA1FCb57eFc9d",
            Chain::Base => "0xf26b0f10691ed160734a3a5caf8ca1fcb57efc9d",
            Chain::Optimism => "0xf26b0f10691ed160734a3a5caf8ca1fcb57efc9d",
            Chain::Avalanche => "0x3A5Dd1FDf3bEdC3a6B3E5A1c0F0b4E2e7B3F1d9a",
            Chain::Polygon => "0x3A5Dd1FDf3bEdC3a6B3E5A1c0F0b4E2e7B3F1d9b",
        }
    }

    pub fn chain_id(&self) -> u64 {
        match self {
            Chain::Ethereum => 1,
            Chain::Arbitrum => 42161,
            Chain::Optimism => 10,
            Chain::Base => 8453,
            Chain::Avalanche => 43114,
            Chain::Polygon => 137,
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Chain::Ethereum => "ethereum",
            Chain::Arbitrum => "arbitrum",
            Chain::Optimism => "optimism",
            Chain::Base => "base",
            Chain::Avalanche => "avalanche",
            Chain::Polygon => "polygon",
        };
        write!(f, "{}", s)
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialStatus {
    Active,
    Expired,
    Blacklisted,
    NotFound,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyringCredential {
    pub wallet: String,
    pub policy_id: u32,
    pub status: CredentialStatus,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub chain: Chain,
    pub is_compliant: bool,
}

impl KeyringCredential {
    pub fn is_valid(&self) -> bool {
        if !self.is_compliant {
            return false;
        }
        match &self.expires_at {
            Some(exp) => *exp > Utc::now(),
            None => true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityCheckResult {
    pub wallet: String,
    pub chain: Chain,
    pub credentials: Vec<KeyringCredential>,
    pub passes_default_policy: bool,
    pub checked_at: DateTime<Utc>,
}


#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Aave,
    Compound,
    Lido,
    Other(String),
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Aave => write!(f, "Aave"),
            Protocol::Compound => write!(f, "Compound"),
            Protocol::Lido => write!(f, "Lido"),
            Protocol::Other(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskTier {
    Low = 1,
    Medium = 2,
    High = 3,
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskTier::Low => write!(f, "Low"),
            RiskTier::Medium => write!(f, "Medium"),
            RiskTier::High => write!(f, "High"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YieldOpportunity {
    pub id: String,
    pub protocol: Protocol,
    pub chain: Chain,
    pub pool_name: String,
    pub pool_address: String,
    pub token_symbol: String,
    pub token_address: String,
    pub apy: Decimal,
    pub tvl_usd: Decimal,
    pub available_liquidity_usd: Decimal,
    pub risk_tier: RiskTier,
    pub has_keyring_gate: bool,
    pub required_policy_id: Option<u32>,
    pub fetched_at: DateTime<Utc>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheckResult {
    pub opportunity_id: String,
    pub is_compliant: bool,
    pub rejection_reasons: Vec<String>,
    pub evaluated_policies: Vec<u32>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapitalRoute {
    pub rank: u32,
    pub opportunity: YieldOpportunity,
    pub recommended_allocation_usd: Decimal,
    pub expected_annual_return_usd: Decimal,
    pub score: Decimal,
    pub compliance: ComplianceCheckResult,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingResult {
    pub wallet: String,
    pub capital_amount_usd: Decimal,
    pub chain: Chain,
    pub identity: IdentityCheckResult,
    pub routes: Vec<CapitalRoute>,
    pub total_opportunities_scanned: usize,
    pub compliance_filtered_count: usize,
    pub computed_at: DateTime<Utc>,
}


#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub keyring_api_key: String,
    pub keyring_api_base_url: String,
    pub graph_api_key: Option<String>,
    pub max_routes: usize,
    pub min_apy: Decimal,
    pub max_risk_tier: RiskTier,
    pub min_tvl_usd: Decimal,
    pub request_timeout_secs: u64,
    pub require_keyring_gate: bool,
}

impl RouterConfig {
    pub fn new(keyring_api_key: impl Into<String>) -> Self {
        Self {
            keyring_api_key: keyring_api_key.into(),
            keyring_api_base_url: "https://api.keyring.network".to_string(),
            graph_api_key: None,
            max_routes: 5,
            min_apy: Decimal::new(1, 2), // 1%
            max_risk_tier: RiskTier::Medium,
            min_tvl_usd: Decimal::new(1_000_000, 0), // $1M
            request_timeout_secs: 30,
            require_keyring_gate: false,
        }
    }

    pub fn with_graph_api_key(mut self, key: impl Into<String>) -> Self {
        self.graph_api_key = Some(key.into());
        self
    }

    pub fn with_max_routes(mut self, n: usize) -> Self {
        self.max_routes = n;
        self
    }

    pub fn with_min_apy(mut self, apy: Decimal) -> Self {
        self.min_apy = apy;
        self
    }

    pub fn with_max_risk_tier(mut self, tier: RiskTier) -> Self {
        self.max_risk_tier = tier;
        self
    }

    pub fn with_min_tvl(mut self, tvl_usd: Decimal) -> Self {
        self.min_tvl_usd = tvl_usd;
        self
    }

    pub fn require_keyring_gate(mut self, require: bool) -> Self {
        self.require_keyring_gate = require;
        self
    }
}