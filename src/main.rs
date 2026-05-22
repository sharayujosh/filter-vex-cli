// use clap::Parser;
// use serde_json::Value;
// use std::fs;

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

fn main() {
    let tf = ExactTextFilter::new("foo");
    println!("{}", tf.equals("bar"));

    //let sample_data = serde_json::from_str(&(fs::read_to_string("sample_vex.json")?))?;
}