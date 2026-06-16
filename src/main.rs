mod cli;
mod cmdi;
mod core;
mod http;
mod pathtrav;
mod payload;
mod reporting;
mod scanner;
mod sqli;
mod ssrf;
mod validation;
// TODO: Fix type errors in xss modules
mod xss;

use cli::args::Cli;
use core::context::Context;
use core::engine::Engine;
use clap::{CommandFactory, Parser};
use std::env;

const BANNER: &str = r#"
 ╔════════════════════════════════════════════════════════════════════╗
 ║                                                                    ║
 ║     █████╗ ███╗   ██╗██╗   ██╗██╗██╗                               ║
 ║    ██╔══██╗████╗  ██║██║   ██║██║██║                               ║
 ║    ███████║██╔██╗ ██║██║   ██║██║██║                               ║
 ║    ██╔══██║██║╚██╗██║╚██╗ ██╔╝██║██║                               ║
 ║    ██║  ██║██║ ╚████║ ╚████╔╝ ██║███████╗                          ║
 ║    ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝╚══════╝                          ║
 ║                                                                    ║
 ║    Enterprise-grade Adversarial Security Testing Framework         ║
 ║                                                                    ║
 ║    Author  : Siddhant Bhattarai                                    ║
 ║    Version : 0.6.0                                                 ║
 ║    License : Apache-2.0                                            ║
 ║                                                                    ║
 ╚════════════════════════════════════════════════════════════════════╝
"#;

fn print_banner() {
    println!("\x1b[36m{}\x1b[0m", BANNER); // Cyan color
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    
    // Check if --help, -h, --version, or -V is requested
    let show_help = args.iter().any(|a| a == "--help" || a == "-h");
    let show_version = args.iter().any(|a| a == "--version" || a == "-V");
    let no_banner = args.iter().any(|a| a == "--no-banner");
    
    // Show banner first for help/version unless --no-banner
    if (show_help || show_version) && !no_banner {
        print_banner();
        
        if show_version && !show_help {
            // Just exit after showing banner for --version
            // The banner already contains version info
            return Ok(());
        }
        
        if show_help {
            // Print help and exit
            Cli::command().print_help()?;
            println!(); // Extra newline
            return Ok(());
        }
    }
    
    // Normal parsing for actual runs
    let cli = Cli::parse();

    // Show banner for normal runs unless --no-banner or --quiet
    if !cli.no_banner && !cli.quiet {
        print_banner();
    }

    tracing_subscriber::fmt::init();

    let ctx = Context::from_cli(cli)?;
    let engine = Engine::new(ctx)?;
    engine.run().await?;

    Ok(())
}
