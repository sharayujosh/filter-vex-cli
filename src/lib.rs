use chrono::{Utc, NaiveDate};
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
        // let mut file = OpenOptions::new()
        // .create(true) // Create the file if it doesn't exist.
        // .append(true) // Seek to end before every write.
        // .open(file_path)?;
        let mut output_file = fs::File::create(file_path)?;
        output_file.write_all(to_write.as_bytes())?;
        Ok(())
    }

    pub fn print_last_updateds(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut to_delete:Vec<usize> = Vec::new();
        let days = 1000;
        if let Some(vul) = self.0.get_mut("vulnerabilities").and_then(|v| v.as_array_mut()) {
            for (id, i) in vul.iter().enumerate() {
                if let Some(a) = i.get("analysis")
                    && let Some(u) = a.get("lastUpdated") {
                        if let Some(x) = u.as_str() {
                            // println!("\n\n LU IS: {:?}", x);
                            let n = NaiveDate::parse_from_str(x.trim_end_matches('Z'), "%Y-%m-%dT%H:%M:%S")?;
                            let today = Utc::now().date_naive();

                            // println!("{}",(today - n).num_days());
                            if (today - n).num_days() > days {
                                to_delete.push(id);
                                println!("{:?}", to_delete);
                            }
                        }
                    }
            }

            for i in to_delete.iter().rev(){
                vul.remove(*i);
            }
            println!("{:?}", vul);

        }
        Ok(())
    }

    // pub fn is_within_bound(lastUpdated:NaiveDate, days:i32) -> bool {
    //     let today = Utc::now().date_naive();
    //     if (today - lastUpdated).num_days() > days {
    //         // println!("{}", (today - lastUpdated).num_days());
    //         false
    //     }
    //     true
    // }
}