
use std::time::Duration;

use chrono::Utc;
use rust_decimal::Decimal;
use rust_decimal::prelude::FromPrimitive;
use tracing::{info, instrument};

use crate::compliance::{ComplianceConfig, ComplianceFilter};
use crate::error::{Result, RouterError};
use crate::keyring_client::KeyringClient;
use crate::models::{
    CapitalRoute, Chain, ComplianceCheckResult, IdentityCheckResult, RiskTier, RouterConfig,
    RoutingResult, YieldOpportunity,
};
use crate::yield_scanner::YieldScanner;

const APY_WEIGHT: f64 = 0.60;
const TVL_WEIGHT: f64 = 0.30;
const RISK_WEIGHT: f64 = 0.10;

pub struct CapitalRouter {
    config: RouterConfig,
    keyring: KeyringClient,
    scanner: YieldScanner,
}

impl CapitalRouter {

    pub fn new(api_key: impl Into<String>) -> Self {
        let config = RouterConfig::new(api_key);
        Self::with_config(config)
    }

    pub fn with_config(config: RouterConfig) -> Self {
        let timeout = Duration::from_secs(config.request_timeout_secs);

        let keyring = KeyringClient::new(
            config.keyring_api_key.clone(),
            config.keyring_api_base_url.clone(),
            timeout,
        );

        let scanner = YieldScanner::new(timeout, config.graph_api_key.clone());

        Self {
            config,
            keyring,
            scanner,
        }
    }

    #[instrument(skip(self), fields(
        wallet = %wallet_address,
        capital = %capital_amount_usd,
        chain = %chain,
    ))]
    pub async fn find_routes(
        &self,
        wallet_address: &str,
        capital_amount_usd: Decimal,
        chain: Chain,
    ) -> Result<RoutingResult> {
        info!(
            "find_routes: wallet={} capital=${} chain={}",
            wallet_address, capital_amount_usd, chain
        );

        let identity = self
            .keyring
            .verify_wallet(wallet_address, &chain)
            .await?;

        if !identity.passes_default_policy {
            return Err(RouterError::IdentityCheckFailed {
                wallet: wallet_address.to_string(),
                reason: "wallet does not pass Keyring default policy".to_string(),
            });
        }

        info!(
            "Identity OK for {}: {} credentials",
            wallet_address,
            identity.credentials.len()
        );

        let raw_opportunities = self.scanner.fetch_opportunities(&chain).await?;
        let total_scanned = raw_opportunities.len();

        if raw_opportunities.is_empty() {
            return Err(RouterError::NoOpportunitiesFound {
                chain: chain.to_string(),
                min_apy: format!("{:.2}%", self.config.min_apy * Decimal::ONE_HUNDRED),
            });
        }

        let compliance_config = ComplianceConfig {
            max_risk_tier: self.config.max_risk_tier.clone(),
            min_tvl_usd: self.config.min_tvl_usd,
            min_apy: self.config.min_apy,
            require_keyring_gate: self.config.require_keyring_gate,
            required_policy_id: None,
        };

        let (compliant, rejected) =
            ComplianceFilter::filter(&identity, raw_opportunities, &compliance_config)?;

        let compliance_filtered = rejected.len();

        if compliant.is_empty() {
            return Err(RouterError::NoCompliantOpportunities {
                total: total_scanned,
            });
        }

        let mut routes = self.rank_opportunities(compliant, capital_amount_usd);
        routes.truncate(self.config.max_routes);

        for (i, route) in routes.iter_mut().enumerate() {
            route.rank = (i + 1) as u32;
        }

        info!(
            "Routing complete: {} routes returned from {} scanned ({} filtered)",
            routes.len(),
            total_scanned,
            compliance_filtered,
        );

        Ok(RoutingResult {
            wallet: wallet_address.to_string(),
            capital_amount_usd,
            chain,
            identity,
            routes,
            total_opportunities_scanned: total_scanned,
            compliance_filtered_count: compliance_filtered,
            computed_at: Utc::now(),
        })
    }


    fn rank_opportunities(
        &self,
        compliant: Vec<(YieldOpportunity, ComplianceCheckResult)>,
        capital: Decimal,
    ) -> Vec<CapitalRoute> {
        // Compute min/max for normalisation
        let apys: Vec<f64> = compliant
            .iter()
            .filter_map(|(o, _)| Decimal::to_f64(&o.apy))
            .collect();
        let tvls: Vec<f64> = compliant
            .iter()
            .filter_map(|(o, _)| Decimal::to_f64(&o.tvl_usd))
            .collect();

        let max_apy = apys.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let min_apy = apys.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_tvl = tvls.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let min_tvl = tvls.iter().cloned().fold(f64::INFINITY, f64::min);

        let normalize = |val: f64, min: f64, max: f64| -> f64 {
            if (max - min).abs() < f64::EPSILON {
                1.0
            } else {
                (val - min) / (max - min)
            }
        };

        let risk_penalty = |tier: &RiskTier| -> f64 {
            match tier {
                RiskTier::Low => 0.0,
                RiskTier::Medium => 0.5,
                RiskTier::High => 1.0,
            }
        };

        let mut scored: Vec<(CapitalRoute, f64)> = compliant
            .into_iter()
            .map(|(opp, compliance)| {
                let apy_f = Decimal::to_f64(&opp.apy).unwrap_or(0.0);
                let tvl_f = Decimal::to_f64(&opp.tvl_usd).unwrap_or(0.0);

                let norm_apy = normalize(apy_f, min_apy, max_apy);
                let norm_tvl = normalize(tvl_f, min_tvl, max_tvl);
                let risk_pen = risk_penalty(&opp.risk_tier);

                let raw_score =
                    APY_WEIGHT * norm_apy + TVL_WEIGHT * norm_tvl - RISK_WEIGHT * risk_pen;

                let score = Decimal::from_f64(raw_score.max(0.0)).unwrap_or_default();
                let expected_return =
                    capital * opp.apy;

                let rationale = Self::build_rationale(&opp, score, norm_apy, norm_tvl);

                let route = CapitalRoute {
                    rank: 0, // set after sort
                    expected_annual_return_usd: expected_return,
                    recommended_allocation_usd: capital,
                    compliance,
                    rationale,
                    score,
                    opportunity: opp,
                };

                (route, raw_score)
            })
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored.into_iter().map(|(r, _)| r).collect()
    }

    fn build_rationale(
        opp: &YieldOpportunity,
        score: Decimal,
        norm_apy: f64,
        norm_tvl: f64,
    ) -> String {
        format!(
            "{} on {} offers {:.2}% APY with ${:.0}M TVL (risk: {:?}). \
            Composite score: {:.4} (APY rank: {:.0}%, TVL rank: {:.0}%).",
            opp.protocol,
            opp.pool_name,
            opp.apy * Decimal::ONE_HUNDRED,
            opp.tvl_usd / Decimal::new(1_000_000, 0),
            opp.risk_tier,
            score,
            norm_apy * 100.0,
            norm_tvl * 100.0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn test_router_builder() {
        let router = CapitalRouter::new("test-key");
        assert_eq!(router.config.max_routes, 5);
        assert_eq!(router.config.max_risk_tier, RiskTier::Medium);
    }

    #[test]
    fn test_router_with_config() {
        let config = RouterConfig::new("test-key")
            .with_max_routes(10)
            .with_min_apy(dec!(0.03))
            .with_max_risk_tier(RiskTier::High);

        let router = CapitalRouter::with_config(config);
        assert_eq!(router.config.max_routes, 10);
        assert_eq!(router.config.min_apy, dec!(0.03));
        assert_eq!(router.config.max_risk_tier, RiskTier::High);
    }
}