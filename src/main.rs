// use clap::Parser;
// use std::fs::File;
use filter_vex_cli::CdkVex;

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

fn main() -> Result<(), Box<dyn std::error::Error>>{
    // let tf = ExactTextFilter::new("foo");
    // println!("{}", tf.equals("bar"));

    let obj: CdkVex = CdkVex::fromJsonFile("json_files/sample_vex.json")?;
    obj.writeJsonFile("json_files/output2.json")?;

    Ok(())
    //let sample_data = serde_json::from_str(&(fs::read_to_string("sample_vex.json")?))?;
}