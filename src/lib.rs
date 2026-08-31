#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::assertions_on_result_states
    )
)]

use chrono::NaiveDate;
use dateparser;
use serde::Deserialize;
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
        let mut output_file = fs::File::create(file_path)?;
        output_file.write_all(to_write.as_bytes())?;
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
                let vv: CdxVulnerability = serde_json::from_value(i.clone())?;
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
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CdxAnalysis {
    first_issued: Option<String>,
    last_updated: Option<String>,
}

#[derive(Deserialize, Debug)]
struct CdxVulnerability {
    analysis: Option<CdxAnalysis>,
    published: Option<String>,
    updated: Option<String>,
    created: Option<String>,
}

impl CdxVulnerability {
    fn match_filter(&self, filter: &CdxVexFilter) -> bool {
        let mut rc = true;
        if let Some(a) = &self.analysis {
            rc = match_to_dates(a.last_updated.clone(), &filter.last_updated)
                && match_to_dates(a.first_issued.clone(), &filter.first_issued)
        }
        rc && match_to_dates(self.published.clone(), &filter.published)
            && match_to_dates(self.updated.clone(), &filter.updated)
            && match_to_dates(self.created.clone(), &filter.created)
    }
}
pub struct CdxVexFilter {
    pub last_updated: Vec<Box<dyn DateComparator>>,
    pub first_issued: Vec<Box<dyn DateComparator>>,
    pub published: Vec<Box<dyn DateComparator>>,
    pub updated: Vec<Box<dyn DateComparator>>,
    pub created: Vec<Box<dyn DateComparator>>,
}

impl CdxVexFilter {
    pub fn new() -> Result<Self> {
        Ok(Self {
            last_updated: Vec::new(),
            first_issued: Vec::new(),
            published: Vec::new(),
            updated: Vec::new(),
            created: Vec::new(),
        })
    }
}

fn match_to_dates(vul_date: Option<String>, date_filters: &Vec<Box<dyn DateComparator>>) -> bool {
    let mut to_return = true;
    let v_date = match vul_date {
        Some(v) => match dateparser::parse(&v) {
            Ok(d) => d.date_naive(),
            _ => return true,
        },
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

/// Creates a date filter based on the provided string.
/// The format of string is as follows:
/// - "<YYYY-MM-DD" for dates less than the specified date
/// - ">YYYY-MM-DD" for dates greater than the specified date
/// - "=YYYY-MM-DD" for dates equal to the specified date
/// - "" (empty string) for an always true filter
///
/// Example usage:
/// ```rust
/// use chrono::NaiveDate;
/// use filter_vex_cli::create_filter;
///
/// let filter = create_filter("<2023-01-01").unwrap();
/// assert!(filter.check_date(&NaiveDate::from_ymd_opt(2022, 12, 31).unwrap()));
/// assert!(!filter.check_date(&NaiveDate::from_ymd_opt(2023, 01, 01).unwrap()));
/// ```
pub fn create_filter(filter_date: &str) -> Result<Box<dyn DateComparator>> {
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
    fn match_test_create_filter() {
        let ex_date = NaiveDate::from_ymd_opt(2019, 1, 10).unwrap();
        let ex_date_m1 = ex_date - Days::new(1);
        let ex_date_p1 = ex_date + Days::new(1);
        let ex_date_eq = ex_date;
        let ltd = create_filter("<2019-01-10").unwrap();
        let gtd = create_filter(">2019-01-10").unwrap();
        let etd = create_filter("=2019-01-10").unwrap();

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

    #[test]
    fn test_vul_filter_pass() {
        let vul = CdxVulnerability {
            analysis: {
                Some(CdxAnalysis {
                    first_issued: Some("2019-01-10T00:00:00".to_string()),
                    last_updated: Some("2020-12-13T00:00:00".to_string()),
                })
            },
            published: Some("2020-12-03T00:00:00.000Z".to_string()),
            created: Some("2019-03-03T00:00:00.000Z".to_string()),
            updated: Some("2020-12-13T00:00:00.000Z".to_string()),
        };
        let ltd = create_filter("<2021-01-10").unwrap();
        let gtd = create_filter(">2018-01-10").unwrap();
        let etd = create_filter("=2020-12-03").unwrap();
        let mut filter = CdxVexFilter::new().unwrap();
        filter.published.push(ltd);
        assert!(vul.match_filter(&filter));
        filter.published.push(gtd);
        assert!(vul.match_filter(&filter));
        filter.published.push(etd);
        assert!(vul.match_filter(&filter));
        let ltd = create_filter("<2021-01-10").unwrap();
        let gtd = create_filter(">2018-01-10").unwrap();
        let etd = create_filter("=2019-03-03").unwrap();
        filter.created.push(ltd);
        assert!(vul.match_filter(&filter));
        filter.created.push(gtd);
        assert!(vul.match_filter(&filter));
        filter.created.push(etd);
        assert!(vul.match_filter(&filter));
        let ltd = create_filter("<2021-01-10").unwrap();
        let gtd = create_filter(">2018-01-10").unwrap();
        let etd = create_filter("=2020-12-13").unwrap();
        filter.updated.push(ltd);
        assert!(vul.match_filter(&filter));
        filter.updated.push(gtd);
        assert!(vul.match_filter(&filter));
        filter.updated.push(etd);
        assert!(vul.match_filter(&filter));
        let ltd = create_filter("<2021-01-10").unwrap();
        let gtd = create_filter(">2018-01-10").unwrap();
        let etd = create_filter("=2020-12-13").unwrap();
        filter.last_updated.push(ltd);
        assert!(vul.match_filter(&filter));
        filter.last_updated.push(gtd);
        assert!(vul.match_filter(&filter));
        filter.last_updated.push(etd);
        assert!(vul.match_filter(&filter));
        let ltd = create_filter("<2021-01-10").unwrap();
        let gtd = create_filter(">2018-01-10").unwrap();
        let etd = create_filter("=2020-12-13").unwrap();
        filter.first_issued.push(ltd);
        assert!(vul.match_filter(&filter));
        filter.first_issued.push(gtd);
        assert!(vul.match_filter(&filter));
        filter.first_issued.push(etd);
        assert!(vul.match_filter(&filter));

        let vul = CdxVulnerability {
            analysis: None,
            published: None,
            created: None,
            updated: None,
        };

        assert!(vul.match_filter(&filter));
    }

    #[test]
    fn test_vul_filter_fails() {
        let vul = CdxVulnerability {
            analysis: {
                Some(CdxAnalysis {
                    first_issued: Some("2019-01-10T00:00:00".to_string()),
                    last_updated: Some("2020-12-13T00:00:00".to_string()),
                })
            },
            published: Some("2020-12-03T00:00:00.000Z".to_string()),
            created: Some("2019-03-03T00:00:00.000Z".to_string()),
            updated: Some("2020-12-13T00:00:00.000Z".to_string()),
        };
        let ltd = create_filter("<2018-01-10").unwrap();
        let gtd = create_filter(">2022-01-10").unwrap();
        let etd = create_filter("=2010-12-03").unwrap();
        let mut filter = CdxVexFilter::new().unwrap();
        filter.published.push(ltd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        filter.published.push(gtd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        filter.published.push(etd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        let ltd = create_filter("<2018-01-10").unwrap();
        let gtd = create_filter(">2022-01-10").unwrap();
        let etd = create_filter("=2011-03-03").unwrap();
        filter.created.push(ltd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        filter.created.push(gtd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        filter.created.push(etd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        let ltd = create_filter("<2018-01-10").unwrap();
        let gtd = create_filter(">2022-01-10").unwrap();
        let etd = create_filter("=2021-12-13").unwrap();
        filter.updated.push(ltd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        filter.updated.push(gtd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        filter.updated.push(etd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        let ltd = create_filter("<2018-01-10").unwrap();
        let gtd = create_filter(">2022-01-10").unwrap();
        let etd = create_filter("=2023-12-13").unwrap();
        filter.last_updated.push(ltd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        filter.last_updated.push(gtd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        filter.last_updated.push(etd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        let ltd = create_filter("<2018-01-10").unwrap();
        let gtd = create_filter(">2022-01-10").unwrap();
        let etd = create_filter("=2019-12-13").unwrap();
        filter.first_issued.push(ltd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        filter.first_issued.push(gtd);
        assert!(!vul.match_filter(&filter));
        filter.published.pop();
        filter.first_issued.push(etd);
        assert!(!vul.match_filter(&filter));
    }
}
