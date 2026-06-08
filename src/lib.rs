use chrono::{Utc, NaiveDate};
use std::fs;
use std::io::Write;
 use std::str::FromStr;
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
                let vv = CdxVulnerability::new(i)?;
                if let Some(n) = vv.get_last_updated() {
                    let today = Utc::now().date_naive();

                    if (today - n).num_days() > days {
                        to_delete.push(id);
                        println!("{:?}", to_delete);
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

    pub fn apply_filter(&mut self, filter: &CdxFilter) -> Result<(), Box<dyn std::error::Error>> {
        let mut to_delete:Vec<usize> = Vec::new();
        if let Some(vul) = self.0.get_mut("vulnerabilities").and_then(|v| v.as_array_mut()) {
            for (id, i) in vul.iter().enumerate() {
                let vv = CdxVulnerability::new(i)?;
                if !vv.match_filter(filter) {
                    to_delete.push(id);
                }
            }

            for i in to_delete.iter().rev(){
                vul.remove(*i);
            }
            println!("{:?}", vul);
        }
        Ok(())
    }
    
}

struct CdxVulnerability {
    last_updated:Option<NaiveDate>,
}

impl CdxVulnerability {
    fn new(var:&serde_json::Value) -> Result<Self, Box<dyn std::error::Error>>  {
        let mut last_updated:Option<NaiveDate> = None;
        if let Some(a) = var.get("analysis")
            && let Some(u) = a.get("lastUpdated") 
                && let Some(x) = u.as_str() {
                    // println!("\n\n LU IS: {:?}", x);
                    last_updated = Some(NaiveDate::parse_from_str(x.trim_end_matches('Z'), "%Y-%m-%dT%H:%M:%S")?);
        }
        
        Ok(
            Self {
                last_updated,
            }
        )
    }

    fn get_last_updated(&self) -> Option<NaiveDate> {
        self.last_updated
    }

    fn match_filter(&self, filter: &CdxFilter) -> bool {
        for f in &filter.last_updated{
            let trimmed = f.trim();
            if trimmed.len() != 11 {
                if trimmed.is_empty() {
                    return true;
                }
                return false;
            }
            let (compatator, date_str) = trimmed.split_at(1); // use split_at_checked & handle 'None' case
            //let split_date:Vec<&str> = date_str.split('-').collect();
            if let Ok(date_naive) = NaiveDate::from_str(date_str) // handle error
                && let Some(last_updated) = self.last_updated { // check before loop, return false if not
                return match compatator {
                    "<" => (last_updated - date_naive).num_days() < 0,
                    ">" => (last_updated - date_naive).num_days() > 0,
                    "=" => last_updated == date_naive,
                    _ => false,
                };
            }
        }
        true
    }
}

fn match_last_updated(last_updated:&NaiveDate, filter:&str) -> bool {
    if filter.is_empty(){
        return false;
    }
    let trimmed = filter.trim();
    let (compatator, date_str) = trimmed.split_at(1);
    if let Ok(date_naive) = date_str.parse::<NaiveDate>() {
        match compatator {
            "<" => (*last_updated - date_naive).num_days() < 0,
            ">" => (*last_updated - date_naive).num_days() > 0,
            "=" => *last_updated == date_naive,
            _ => false,
        }
    } else {
        false
    }
}

pub struct CdxFilter {
    pub last_updated:Vec<String>,
}

impl CdxFilter {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>>  {
        Ok (
            Self {
                last_updated: Vec::new(),
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn match_last_updated_matches_expected_comparisons() {
        let last_updated = NaiveDate::from_ymd_opt(2024, 1, 10).unwrap();

        assert!(match_last_updated(&last_updated, "=2024-01-10"));
        assert!(match_last_updated(&last_updated, "<2024-01-20"));
        assert!(match_last_updated(&last_updated, ">2024-01-01"));
    }

    #[test]
    fn match_last_updated_rejects_non_matching_and_invalid_filters() {
        let last_updated = NaiveDate::from_ymd_opt(2024, 1, 10).unwrap();

        assert!(!match_last_updated(&last_updated, "<2024-01-01"));
        assert!(!match_last_updated(&last_updated, ">2024-01-20"));
        assert!(!match_last_updated(&last_updated, "=bad-date"));
        assert!(!match_last_updated(&last_updated, ""));
    }
}
