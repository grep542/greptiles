pub mod compliance;
pub mod error;
pub mod keyring_client;
pub mod models;
pub mod router;
pub mod yield_scanner;

pub use error::{Result, RouterError};

pub use models::{
    CapitalRoute,
    Chain,
    ComplianceCheckResult,
    CredentialStatus,
    IdentityCheckResult,
    KeyringCredential,
    Protocol,
    RiskTier,
    RouterConfig,
    RoutingResult,
    YieldOpportunity,
};

pub use router::CapitalRouter;
pub use keyring_client::KeyringClient;
pub use yield_scanner::YieldScanner;
pub use compliance::{ComplianceConfig, ComplianceFilter};

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}