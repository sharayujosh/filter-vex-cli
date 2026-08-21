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

mod error;

pub use error::CdxVexError;

pub type Result<T> = std::result::Result<T, CdxVexError>;

pub struct CdxVex(Value);

impl CdxVex {
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

    fn match_filter(&self, filter: &CdxVexFilter) -> bool {
        match_to_dates(self.last_updated, &filter.last_updated)
            && match_to_dates(self.first_issued, &filter.first_issued)
    }
}

pub struct CdxVexFilter {
    pub last_updated: Vec<Box<dyn DateComparator>>,
    pub first_issued: Vec<Box<dyn DateComparator>>,
}

impl CdxVexFilter {
    pub fn new() -> Result<Self> {
        Ok(Self {
            last_updated: Vec::new(),
            first_issued: Vec::new(),
        })
    }
}

fn match_to_dates(
    vul_date: Option<NaiveDate>,
    date_filters: &Vec<Box<dyn DateComparator>>,
) -> bool {
    let mut to_return = true;
    let v_date = match vul_date {
        Some(v) => v,
        None => return true,
    };
    for f in date_filters {
        if to_return {
            to_return = to_return && f.check_date(&v_date);
        } else {
            return false;
        }
    }
    to_return
}

pub trait DateComparator {
    fn check_date(&self, date: &NaiveDate) -> bool;
}

struct LessThanDate {
    anchor_date: NaiveDate,
}

impl DateComparator for LessThanDate {
    fn check_date(&self, date: &NaiveDate) -> bool {
        (*date - self.anchor_date).num_days() < 0
    }
}

struct GreaterThanDate {
    anchor_date: NaiveDate,
}

impl DateComparator for GreaterThanDate {
    fn check_date(&self, date: &NaiveDate) -> bool {
        (*date - self.anchor_date).num_days() > 0
    }
}

struct EqualToDate {
    anchor_date: NaiveDate,
}

impl DateComparator for EqualToDate {
    fn check_date(&self, date: &NaiveDate) -> bool {
        (*date - self.anchor_date).num_days() == 0
    }
}

struct AlwaysTrue {}

impl DateComparator for AlwaysTrue {
    fn check_date(&self, _date: &NaiveDate) -> bool {
        true
    }
}

pub fn filter_creator(filter_date: &str) -> Result<Box<dyn DateComparator>> {
    if filter_date.is_empty() {
        return Err(CdxVexError::InvalidDateFilter(filter_date.to_string()));
    }
    let trimmed = filter_date.trim();
    if trimmed.len() != 11 {
        // check that the date is appropriate num of chars
        if trimmed.is_empty() {
            return Ok(Box::new(AlwaysTrue {}));
        }
        return Err(CdxVexError::InvalidDateFilter(filter_date.to_string()));
    }
    let (comparator, date_str) = trimmed.split_at(1);
    if let Ok(date_naive) = date_str.parse::<NaiveDate>() {
        match comparator {
            "<" => {
                return Ok(Box::new(LessThanDate {
                    anchor_date: date_naive,
                }));
            }
            ">" => {
                return Ok(Box::new(GreaterThanDate {
                    anchor_date: date_naive,
                }));
            }
            "=" => {
                return Ok(Box::new(EqualToDate {
                    anchor_date: date_naive,
                }));
            }
            _ => return Err(CdxVexError::InvalidDateFilter(filter_date.to_string())),
        };
    }
    return Err(CdxVexError::InvalidDateFilter(filter_date.to_string()));
}

#[cfg(test)]
mod tests {

    use super::*;
    use chrono::{Days, NaiveDate};

    #[test]
    fn match_less_than() {
        let ex_date = NaiveDate::from_ymd_opt(2019, 1, 10).unwrap();
        let ex_date_m1 = ex_date - Days::new(1);
        let ex_date_p1 = ex_date + Days::new(1);
        let ex_date_eq = ex_date;
        let ltd = LessThanDate {
            anchor_date: ex_date,
        };
        assert!(ltd.check_date(&ex_date_m1));
        assert!(!ltd.check_date(&ex_date_p1));
        assert!(!ltd.check_date(&ex_date_eq));
    }

    #[test]
    fn match_greater_than() {
        let ex_date = NaiveDate::from_ymd_opt(2019, 1, 10).unwrap();
        let ex_date_m1 = ex_date - Days::new(1);
        let ex_date_p1 = ex_date + Days::new(1);
        let ex_date_eq = ex_date;
        let gtd = GreaterThanDate {
            anchor_date: ex_date,
        };
        assert!(!gtd.check_date(&ex_date_m1));
        assert!(gtd.check_date(&ex_date_p1));
        assert!(!gtd.check_date(&ex_date_eq));
    }

    #[test]
    fn match_equal_to() {
        let ex_date = NaiveDate::from_ymd_opt(2019, 1, 10).unwrap();
        let ex_date_m1 = ex_date - Days::new(1);
        let ex_date_p1 = ex_date + Days::new(1);
        let ex_date_eq = ex_date;
        let etd = EqualToDate {
            anchor_date: ex_date,
        };
        assert!(!etd.check_date(&ex_date_m1));
        assert!(!etd.check_date(&ex_date_p1));
        assert!(etd.check_date(&ex_date_eq));
    }

    #[test]
    fn match_test_filter_creator() {
        let ex_date = NaiveDate::from_ymd_opt(2019, 1, 10).unwrap();
        let ex_date_m1 = ex_date - Days::new(1);
        let ex_date_p1 = ex_date + Days::new(1);
        let ex_date_eq = ex_date;
        let ltd = filter_creator("<2019-01-10").unwrap();
        let gtd = filter_creator(">2019-01-10").unwrap();
        let etd = filter_creator("=2019-01-10").unwrap();

        assert!(ltd.check_date(&ex_date_m1));
        assert!(!ltd.check_date(&ex_date_p1));
        assert!(!ltd.check_date(&ex_date_eq));

        assert!(!gtd.check_date(&ex_date_m1));
        assert!(gtd.check_date(&ex_date_p1));
        assert!(!gtd.check_date(&ex_date_eq));

        assert!(!etd.check_date(&ex_date_m1));
        assert!(!etd.check_date(&ex_date_p1));
        assert!(etd.check_date(&ex_date_eq));
    }
}
