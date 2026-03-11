use clap::{Parser, ValueEnum};
use greptiles::{CapitalRouter, Chain, RouterConfig, RiskTier};
use rust_decimal::Decimal;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(
    name = "greptiles",
    about = "Compliance-aware DeFi capital router powered by Keyring Network",
    version = "0.1.0"
)]
struct Args {
    #[arg(short, long)]
    wallet: String,

    #[arg(short, long)]
    capital: f64,

    #[arg(short = 'n', long, default_value = "ethereum")]
    chain: ChainArg,

    #[arg(short, long, default_value = "medium")]
    risk: RiskArg,

    #[arg(long, default_value = "5")]
    routes: usize,

    #[arg(long, default_value = "1")]
    min_apy: f64,

    #[arg(long, default_value = "1000000")]
    min_tvl: f64,

    #[arg(long, default_value = "false")]
    gated_only: bool,

    #[arg(long, default_value = "false")]
    json: bool,
}

#[derive(Debug, Clone, ValueEnum)]
enum ChainArg {
    Ethereum,
    Arbitrum,
    Optimism,
    Base,
    Avalanche,
    Polygon,
}

impl From<ChainArg> for Chain {
    fn from(c: ChainArg) -> Self {
        match c {
            ChainArg::Ethereum => Chain::Ethereum,
            ChainArg::Arbitrum => Chain::Arbitrum,
            ChainArg::Optimism => Chain::Optimism,
            ChainArg::Base => Chain::Base,
            ChainArg::Avalanche => Chain::Avalanche,
            ChainArg::Polygon => Chain::Polygon,
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum RiskArg {
    Low,
    Medium,
    High,
}

impl From<RiskArg> for RiskTier {
    fn from(r: RiskArg) -> Self {
        match r {
            RiskArg::Low => RiskTier::Low,
            RiskArg::Medium => RiskTier::Medium,
            RiskArg::High => RiskTier::High,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    greptiles::init_tracing();

    let args = Args::parse();

    let api_key = std::env::var("KEYRING_API_KEY").unwrap_or_else(|_| {
        eprintln!("⚠️  KEYRING_API_KEY not set — using demo mode");
        "demo-key".to_string()
    });
    let graph_key = std::env::var("GRAPH_API_KEY").ok();

    let capital = Decimal::from_str(&args.capital.to_string())?;
    let chain: Chain = args.chain.into();
    let risk: RiskTier = args.risk.into();

    let config = RouterConfig::new(api_key)
        .with_max_routes(args.routes)
        .with_min_apy(Decimal::from_str(&(args.min_apy / 100.0).to_string())?)
        .with_min_tvl(Decimal::from_str(&args.min_tvl.to_string())?)
        .with_max_risk_tier(risk)
        .require_keyring_gate(args.gated_only);

    let config = if let Some(key) = graph_key {
        config.with_graph_api_key(key)
    } else {
        config
    };

    let router = CapitalRouter::with_config(config);

    if !args.json {
        println!("\n🔍  Greptiles — Compliance-Aware Capital Router");
        println!("    Wallet:  {}", args.wallet);
        println!("    Capital: ${:.0}", args.capital);
        println!("    Chain:   {}\n", chain);
    }

    match router.find_routes(&args.wallet, capital, chain).await {
        Ok(result) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&result)?);
                return Ok(());
            }

            println!(
                "✅  Identity verified  |  {} scanned  |  {} filtered by compliance  |  {} routes\n",
                result.total_opportunities_scanned,
                result.compliance_filtered_count,
                result.routes.len(),
            );

            if result.routes.is_empty() {
                println!("⚠️  No compliant routes found. Try lowering --min-apy or --min-tvl.");
                return Ok(());
            }

            for route in &result.routes {
                let opp = &route.opportunity;
                let apy_pct = opp.apy * Decimal::from(100);

                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!(
                    "  #{} {:?} — {}",
                    route.rank, opp.protocol, opp.pool_name
                );
                println!("  APY:             {:.2}%", apy_pct);
                println!(
                    "  TVL:             ${:.1}M",
                    opp.tvl_usd / Decimal::from(1_000_000)
                );
                println!("  Risk tier:       {:?}", opp.risk_tier);
                println!("  Keyring gated:   {}", opp.has_keyring_gate);
                println!(
                    "  Expected return: ${:.2} / year on ${:.0}",
                    route.expected_annual_return_usd, args.capital
                );
                println!("  Score:           {:.4}", route.score);
                println!("  💡 {}", route.rationale);
            }

            println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  Computed at: {}", result.computed_at);
        }
        Err(e) => {
            if args.json {
                println!("{{\"error\": \"{}\"}}", e);
            } else {
                eprintln!("\n❌  Error: {}", e);
                eprintln!("    Make sure your wallet has a valid Keyring credential.");
                eprintln!("    See: https://keyring.network\n");
            }
            std::process::exit(1);
        }
    }

    Ok(())
}
