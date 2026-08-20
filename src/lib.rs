#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::assertions_on_result_states
    )
)]

use chrono::{NaiveDate, Utc};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::str::FromStr;

mod error;

pub use error::CdxVexError;

pub type Result<T> = std::result::Result<T, CdxVexError>;

pub struct CdxVex(Value);

impl CdxVex {
    // fn new(value: Value) -> Self {
    //     Cdx
    //Vex(value)
    // }

    pub fn from_json_file(file_path: &str) -> Result<Self> {
        let data_str = fs::read_to_string(file_path)?;
        let sample_data: Value = serde_json::from_str(&data_str)?;
        Ok(CdxVex(sample_data))
    }

    pub fn write_json_file(&self, file_path: &str) -> Result<()> {
        let to_write = serde_json::to_string_pretty(&self.0)?;
        // let mut file = OpenOptions::new()
        // .create(true) // Create the file if it doesn't exist.
        // .append(true) // Seek to end before every write.
        // .open(file_path)?;
        let mut output_file = fs::File::create(file_path)?;
        output_file.write_all(to_write.as_bytes())?;
        Ok(())
    }

    pub fn print_last_updateds(&mut self) -> Result<()> {
        let mut to_delete: Vec<usize> = Vec::new();
        let days = 1000;
        if let Some(vul) = self
            .0
            .get_mut("vulnerabilities")
            .and_then(|v| v.as_array_mut())
        {
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

            for i in to_delete.iter().rev() {
                vul.remove(*i);
            }
            println!("{:?}", vul);
        }
        Ok(())
    }

    pub fn apply_filter(&mut self, filter: &CdxVexFilter) -> Result<()> {
        let mut to_delete: Vec<usize> = Vec::new();
        if let Some(vul) = self
            .0
            .get_mut("vulnerabilities")
            .and_then(|v| v.as_array_mut())
        {
            for (id, i) in vul.iter().enumerate() {
                let vv = CdxVulnerability::new(i)?;
                if !vv.match_filter(filter) {
                    to_delete.push(id);
                }
            }

            for i in to_delete.iter().rev() {
                vul.remove(*i);
            }
            println!("{:?}", vul);
        }
        Ok(())
    }
}

struct CdxVulnerability {
    last_updated: Option<NaiveDate>,
    first_issued: Option<NaiveDate>,
}

impl CdxVulnerability {
    fn new(var: &serde_json::Value) -> Result<Self> {
        let mut last_updated: Option<NaiveDate> = None;
        if let Some(a) = var.get("analysis")
            && let Some(u) = a.get("lastUpdated")
            && let Some(x) = u.as_str()
        {
            // println!("\n\n LU IS: {:?}", x);
            last_updated = Some(NaiveDate::parse_from_str(
                x.trim_end_matches('Z'),
                "%Y-%m-%dT%H:%M:%S",
            )?);
        }
        let mut first_issued: Option<NaiveDate> = None;
        if let Some(a) = var.get("analysis")
            && let Some(u) = a.get("firstIssued")
            && let Some(x) = u.as_str()
        {
            // println!("\n\n LU IS: {:?}", x);
            first_issued = Some(NaiveDate::parse_from_str(
                x.trim_end_matches('Z'),
                "%Y-%m-%dT%H:%M:%S",
            )?);
        }

        Ok(Self {
            last_updated,
            first_issued,
        })
    }

    fn get_last_updated(&self) -> Option<NaiveDate> {
        self.last_updated
    }

    fn get_first_issued(&self) -> Option<NaiveDate> {
        self.first_issued
    }

    fn match_filter(&self, filter: &CdxVexFilter) -> bool {
        return self.match_last_updated(filter) && self.match_first_issued(filter);
    }

    fn match_last_updated(&self, filter: &CdxVexFilter) -> bool {
        let mut to_return = true;
        for f in &filter.last_updated {
            if to_return {
                if let Some(last_updated) = self.last_updated {
                    to_return = to_return && match_date(&last_updated, f);
                }
            } else {
                return false;
            }
        }
        to_return
    }

    fn match_first_issued(&self, filter: &CdxVexFilter) -> bool {
        let mut to_return = true;
        for f in &filter.first_issued {
            if to_return {
                if let Some(first_issued) = self.first_issued {
                    to_return = to_return && match_date(&first_issued, f);
                }
            } else {
                return false;
            }
        }
        to_return
    }
}

pub struct CdxVexFilter {
    pub last_updated: Vec<String>,
    pub first_issued: Vec<String>,
}

impl CdxVexFilter {
    pub fn new() -> Result<Self> {
        Ok(Self {
            last_updated: Vec::new(),
            first_issued: Vec::new(),
        })
    }
}

// ---------- TEST LOGIC FUNCTIONS -----------

fn match_date(date: &NaiveDate, filter_date: &str) -> bool {
    if filter_date.is_empty() {
        return false;
    }
    let trimmed = filter_date.trim();
    if trimmed.len() != 11 {
        // check that the date is appropriate num of chars
        if trimmed.is_empty() {
            return true;
        }
        return false;
    }
    let (compatator, date_str) = trimmed.split_at(1);
    if let Ok(date_naive) = date_str.parse::<NaiveDate>() {
        match compatator {
            "<" => (*date - date_naive).num_days() < 0,
            ">" => (*date - date_naive).num_days() > 0,
            "=" => *date == date_naive,
            _ => false,
        }
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn match_last_updated_matches_expected_comparisons() {
        let last_updated = NaiveDate::from_ymd_opt(2024, 1, 10).unwrap();

        assert!(match_date(&last_updated, "=2024-01-10"));
        assert!(match_date(&last_updated, "<2024-01-20"));
        assert!(match_date(&last_updated, ">2024-01-01"));
    }

    #[test]
    fn match_last_updated_rejects_non_matching_and_invalid_filters() {
        let last_updated = NaiveDate::from_ymd_opt(2024, 1, 10).unwrap();

        assert!(!match_date(&last_updated, "<2024-01-01"));
        assert!(!match_date(&last_updated, ">2024-01-20"));
        assert!(!match_date(&last_updated, "=bad-date"));
        assert!(!match_date(&last_updated, ""));
    }

    #[test]
    fn match_first_issued_matches_expected_comparisons() {
        let first_issued = NaiveDate::from_ymd_opt(2019, 1, 10).unwrap();

        assert!(match_date(&first_issued, "=2019-01-10"));
        assert!(match_date(&first_issued, "<2019-01-20"));
        assert!(match_date(&first_issued, ">2019-01-01"));
    }

    #[test]
    fn match_first_issued_rejects_non_matching_and_invalid_filters() {
        let first_issued = NaiveDate::from_ymd_opt(2019, 1, 10).unwrap();

        assert!(!match_date(&first_issued, "<2019-01-01"));
        assert!(!match_date(&first_issued, ">2019-01-20"));
        assert!(!match_date(&first_issued, "=bad-date"));
        assert!(!match_date(&first_issued, ""));
    }
}
