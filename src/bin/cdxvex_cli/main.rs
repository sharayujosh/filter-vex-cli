#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::assertions_on_result_states
    )
)]

use filter_vex_cli::{CdxVex, CdxVexFilter};

// struct ExactTextFilter {
//     pattern: String,
// }

// impl ExactTextFilter {
//     fn new(x: &str) -> Self {
//         Self {
//             pattern:String::from(x)
//         }
//     }

//     fn equals(&self, x: &str) -> bool {
//         x == self.pattern
//     }
// }

// filters on severity of vulnerability
// fn severity(vex_data: &Value, &str severity: String) -> Self {
//     // Implementation for severity filter
//     let vuln = vex_data.get("vulnerabilities")?.as_array()?;
// }

// unit test of 'severity' function for VEX files
// fn

use clap::Parser;
use miette::{IntoDiagnostic, Result};

#[derive(Parser, Debug)]
#[command(name = "cdxvex_cli", version, about = "CycloneDx VEX filter")]
struct Args {
    // Input file address
    #[arg(short, long)]
    input_file: String,

    // Output file address
    #[arg(short, long)]
    output_file: String,

    // date filter
    #[arg(short, long, value_delimiter = ' ', num_args = 1..)]
    last_updated_filter: Option<Vec<String>>,

    // date filter
    #[arg(short, long, value_delimiter = ' ', num_args = 1..)]
    first_issued_filter: Option<Vec<String>>,
}

fn main() -> Result<()> {
    // let tf = ExactTextFilter::new("foo");
    // println!("{}", tf.equals("bar"));

    let args = Args::parse();

    let mut obj: CdxVex = CdxVex::from_json_file(&args.input_file).into_diagnostic()?;

    //obj.print_last_updateds()?;
    let mut filter: CdxVexFilter = CdxVexFilter::new().into_diagnostic()?;
    if let Some(date_filter) = args.last_updated_filter {
        for f in date_filter {
            filter.last_updated.push(f);
        }
    }
    if let Some(date_filter) = args.first_issued_filter {
        for f in date_filter {
            filter.first_issued.push(f);
        }
    }
    obj.apply_filter(&filter).into_diagnostic()?;
    obj.write_json_file(&args.output_file).into_diagnostic()?;

    Ok(())
    //let sample_data = serde_json::from_str(&(fs::read_to_string("sample_vex.json")?))?;
}
