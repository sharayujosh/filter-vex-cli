use std::fs;
use std::io::Write;
use serde_json::Value;

pub struct CdkVex(Value);

impl CdkVex {
    fn new(value: Value) -> Self {
        CdkVex(value)
    }

    pub fn fromJsonFile(file_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data_str = fs::read_to_string(file_path)?;
        let sample_data: Value = serde_json::from_str(&data_str)?;
        Ok(CdkVex(sample_data))
    }

    pub fn writeJsonFile(&self, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let to_write = serde_json::to_string_pretty(&self.0)?;
        let mut output_file = fs::File::create(file_path)?;
        output_file.write_all(to_write.as_bytes())?;
        Ok(())
    }
}