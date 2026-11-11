//! `scope-engine` CLI.
//!
//! Subcommands: `serve`, `check`, `egress`, `health`, `version`.

use std::io::Read;
use std::net::SocketAddr;

use clap::{Parser, Subcommand};

use scope_engine::model::{Decision, ScopeRequest};
use scope_engine::{egress, engine, server};

#[derive(Parser)]
#[command(
    name = "scope-engine",
    version = env!("CARGO_PKG_VERSION"),
    about = "FFUF Online Scope Enforcement Engine — the only place scope decisions are made"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the HTTP server (bind address from SCOPE_ENGINE_ADDR).
    Serve,
    /// Evaluate a ScopeRequest JSON document (file or stdin) and print the decision.
    Check {
        /// Path to a JSON file, or `-` / omitted for stdin.
        #[arg(long)]
        input: Option<String>,
    },
    /// Authorize egress for a ScopeRequest JSON document.
    Egress {
        /// Path to a JSON file, or `-` / omitted for stdin.
        #[arg(long)]
        input: Option<String>,
    },
    /// Print `ok` and exit 0.
    Health,
    /// Print the crate version.
    Version,
}

fn error_json(detail: &str) -> String {
    serde_json::json!({ "error": "invalid_request", "detail": detail }).to_string()
}

fn read_input(input: &Option<String>) -> anyhow::Result<String> {
    match input.as_deref() {
        None | Some("-") => {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            Ok(buf)
        }
        Some(path) => Ok(std::fs::read_to_string(path)?),
    }
}

fn run_decision(input: Option<String>, egress_mode: bool) {
    let raw = match read_input(&input) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("{}", error_json(&e.to_string()));
            std::process::exit(1);
        }
    };

    let req: ScopeRequest = match serde_json::from_str(&raw) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("{}", error_json(&e.to_string()));
            std::process::exit(1);
        }
    };

    let decision = if egress_mode {
        egress::authorize_egress(&req)
    } else {
        engine::evaluate(&req)
    };

    match serde_json::to_string(&decision) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("{}", error_json(&e.to_string()));
            std::process::exit(1);
        }
    }

    if decision.decision == Decision::Approved {
        std::process::exit(0);
    } else {
        std::process::exit(2);
    }
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).try_init();
}

fn run_serve() {
    let addr_str = std::env::var("SCOPE_ENGINE_ADDR").unwrap_or_else(|_| "127.0.0.1:8090".to_string());
    let addr: SocketAddr = match addr_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("{}", error_json(&format!("invalid SCOPE_ENGINE_ADDR `{}`: {}", addr_str, e)));
            std::process::exit(1);
        }
    };

    init_tracing();

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{}", error_json(&e.to_string()));
            std::process::exit(1);
        }
    };

    if let Err(e) = runtime.block_on(server::serve(addr)) {
        eprintln!("{}", error_json(&e.to_string()));
        std::process::exit(1);
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Serve => run_serve(),
        Commands::Check { input } => run_decision(input, false),
        Commands::Egress { input } => run_decision(input, true),
        Commands::Health => println!("ok"),
        Commands::Version => println!("{}", env!("CARGO_PKG_VERSION")),
    }
}
