// use clap::Parser;
// use std::fs::File;
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

#[derive(Parser, Debug)]
struct Args {
    // Input file address
    #[arg(short, long)]
    input_file: String,

    // Output file address
    #[arg(short, long)]
    output_file: String,

    // date filter
    #[arg(short, long)]
    last_updated_filter: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let tf = ExactTextFilter::new("foo");
    // println!("{}", tf.equals("bar"));

    let args = Args::parse();

    let mut obj: CdxVex = CdxVex::from_json_file(&args.input_file)?;

    //obj.print_last_updateds()?;
    let mut filter: CdxVexFilter = CdxVexFilter::new()?;
    if let Some(date_filter) = args.last_updated_filter {
        filter.last_updated.push(date_filter);
    }
    obj.apply_filter(&filter)?;

    obj.write_json_file(&args.output_file)?;

    Ok(())
    //let sample_data = serde_json::from_str(&(fs::read_to_string("sample_vex.json")?))?;
}
