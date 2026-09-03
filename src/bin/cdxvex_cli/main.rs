#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::assertions_on_result_states
    )
)]

use clap::{Parser, Subcommand};
use filter_vex_cli::{CdxVex, CdxVexFilter, create_filter};
use miette::{IntoDiagnostic, Result};

#[derive(Parser, Debug)]
#[command(name = "cdxvex_cli", version, about = "CycloneDx VEX filter")]
struct Args {
    #[command(subcommand)]
    command: Commands,

    // Input file address
    #[arg(short, long)]
    input_file: String,

    // Output file address
    #[arg(short, long)]
    output_file: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Add a filter
    Filter {
        // ----- date filters -----
        #[arg(short, long, value_delimiter = ' ', num_args = 1..)]
        last_updated_filter: Option<Vec<String>>,
        #[arg(short, long, value_delimiter = ' ', num_args = 1..)]
        first_issued_filter: Option<Vec<String>>,
        #[arg(short, long, value_delimiter = ' ', num_args = 1..)]
        published_filter: Option<Vec<String>>,
        #[arg(short, long, value_delimiter = ' ', num_args = 1..)]
        updated_filter: Option<Vec<String>>,
        #[arg(short, long, value_delimiter = ' ', num_args = 1..)]
        created_filter: Option<Vec<String>>,
    },
}
fn main() -> Result<()> {
    let args = Args::parse();
    let mut obj: CdxVex = CdxVex::from_json_file(&args.input_file).into_diagnostic()?;
    let mut filter: CdxVexFilter = CdxVexFilter::new().into_diagnostic()?;

    match args.command {
        Commands::Filter {
            last_updated_filter,
            first_issued_filter,
            published_filter,
            updated_filter,
            created_filter,
        } => {
            if let Some(date_filter) = last_updated_filter {
                for f in date_filter {
                    filter
                        .last_updated
                        .push(create_filter(f.as_str()).into_diagnostic()?);
                }
            }
            if let Some(date_filter) = first_issued_filter {
                for f in date_filter {
                    filter
                        .first_issued
                        .push(create_filter(f.as_str()).into_diagnostic()?);
                }
            }
            if let Some(date_filter) = published_filter {
                for f in date_filter {
                    filter
                        .published
                        .push(create_filter(f.as_str()).into_diagnostic()?);
                }
            }
            if let Some(date_filter) = updated_filter {
                for f in date_filter {
                    filter
                        .updated
                        .push(create_filter(f.as_str()).into_diagnostic()?);
                }
            }
            if let Some(date_filter) = created_filter {
                for f in date_filter {
                    filter
                        .created
                        .push(create_filter(f.as_str()).into_diagnostic()?);
                }
            }
        }
    }
    obj.apply_filter(&filter).into_diagnostic()?;
    obj.write_json_file(&args.output_file).into_diagnostic()?;

    Ok(())
}
