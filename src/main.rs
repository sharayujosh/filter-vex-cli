// use clap::Parser;
use std::fs::File;
use std::fs;
use std::io::Write;
use serde_json::Value;

struct ExactTextFilter {
    pattern: String,
}

impl ExactTextFilter {
    fn new(x: &str) -> Self {
        Self {
            pattern:String::from(x)
        }
    }

    fn equals(&self, x: &str) -> bool {
        x == self.pattern
    }
}

// filters on severity of vulnerability
// fn severity(vex_data: &Value, &str severity: String) -> Self {
//     // Implementation for severity filter
//     let vuln = vex_data.get("vulnerabilities")?.as_array()?;
// }

// unit test of 'severity' function for VEX files
// fn 

fn main() -> Result<(), Box<dyn std::error::Error>>{
    // let tf = ExactTextFilter::new("foo");
    // println!("{}", tf.equals("bar"));

    let data_str = fs::read_to_string("json_files/sample_vex.json")?;
    let sample_data: Value = serde_json::from_str(&data_str)?;
    let to_write = serde_json::to_string_pretty(&sample_data)?;

    let mut output_file = File::create("json_files/output.json")?;
    output_file.write_all(to_write.as_bytes())?;

    Ok(())
    //let sample_data = serde_json::from_str(&(fs::read_to_string("sample_vex.json")?))?;
}