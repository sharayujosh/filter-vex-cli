# filter-vex-cli

## Phase 0

Read json file into json and write out. Use serde_json crate.

## Phase 1

Define CdxVex newtype class that has json attribute, two methods fromJsonFile and writeJsonFile.
Read VEX json file into json and write out. Use serde_json crate.

## Phase 2

For each vulnerability, find analysis--> last updated, and print it.

## Phase 3

Convert the date to chrono::Naive_Date. Print.

## Phase 4

If date is >30 days ago, delete the entry.

## Phase 5

Define struct CdxVulnerability built w/ lastUpdated as NaiveDate. Need from method that takes Value, getter method for lastUpdated.

## Phase 6

- Create a CdxFilter struct with "pub lastUpdate: Vec\<String>" attribute with a "new" method to construct empty array. You can append filtering strings to the attribute directly. See below for the contents of the string.
- For your CdxVulnerability class, create a function "match_filter(filter: &CdxFilter) -> bool". This borrows the filter and does not own it.
- The match_filter function should do the following for each entry of the filter vector: Trim the string. Support the following formats: "<2025-12-31", ">2025-12-31", "=2026-12-31". The meaning should be obvious. If a filter does not match, return false immediately. If all match, at the end return true. If vector is empty, return true.
- Add new method apply_filter(filter: &CdxFilter) to your main CdxVex struct. It should iterate through each vulnerability, make a new CdxVulnerability struct and call match_filter on it. If result is false, mark that entry for deletion and then delete it.

## P 7

Cli, req in/out file -i-o else die. no filter, lastupdate (takes string of filter bounds). Use clap & miette

## P 8

mult filters (LUGre, LULess)
