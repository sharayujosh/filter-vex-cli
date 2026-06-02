use chrono::NaiveDate;
use std::fs;
use std::io::Write;
use serde_json::Value;

pub struct CdkVex(Value);

impl CdkVex {
    // fn new(value: Value) -> Self {
    //     CdkVex(value)
    // }

    pub fn from_json_file(file_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data_str = fs::read_to_string(file_path)?;
        let sample_data: Value = serde_json::from_str(&data_str)?;
        Ok(CdkVex(sample_data))
    }

    pub fn write_json_file(&self, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let to_write = serde_json::to_string_pretty(&self.0)?;
        let mut output_file = fs::File::create(file_path)?;
        output_file.write_all(to_write.as_bytes())?;
        Ok(())
    }

    pub fn print_last_updateds(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(vul) = self.0.get("vulnerabilities").and_then(|v| v.as_array()) {
            for v in vul.iter() {
                if let Some(a) = v.get("analysis")
                    && let Some(u) = a.get("lastUpdated") {
                        if let Some(mut x) = u.as_str() {
                            println!("\n\n LU IS: {:?}", x);
                            let n = NaiveDate::parse_from_str(x.trim_end_matches('Z'), "%Y-%m-%dT%H:%M:%S")?;
                            println!("\n\n LU IS: {:?}", n);
                        }
                        
                        // let n = NaiveDate::parse_from_str(&u.to_string().trim_end_matches('Z'), "%Y-%m-%dT%H:%M:%S");
                        // println!("\n\n LU IS: {:?}", n);
                    }
            }
        }
        Ok(())
    }
}