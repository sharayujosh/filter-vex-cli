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
