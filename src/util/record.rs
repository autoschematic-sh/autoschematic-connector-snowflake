use std::any::type_name;

use serde::de::DeserializeOwned;
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum JsonTableError {
    #[error("expected JsonResult.value to be an array of rows, got: {0}")]
    NotAnArray(&'static str),

    #[error("expected row {row} to be an array, got: {got}")]
    RowNotAnArray { row: usize, got: &'static str },

    #[error("column not in result: {0}")]
    UnknownColumn(String),

    #[error("column {col} (index {idx}) missing in row {row}")]
    MissingCell { col: String, idx: usize, row: usize },

    #[error("failed to parse column {col} in row {row}: {source}")]
    DeserializeCell {
        col: String,
        row: usize,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to parse column {col} in row {row} as type {type}: {source}")]
    DeserializeTypedCell {
        col: String,
        r#type: String,
        row: usize,
        #[source]
        source: serde_json::Error,
    },
}

/// View over a query result's row.
pub struct RecordRef<'a> {
    schema: &'a [snowflake_api::FieldSchema],
    row: &'a [Value],
    row_idx: usize,
}

impl<'a> RecordRef<'a> {
    fn col_index(&self, name: &str) -> Option<usize> {
        self.schema.iter().position(|c| &c.name == name)
    }

    pub fn get(&self, name: &str) -> Option<&'a Value> {
        let idx = self.col_index(name)?;
        self.row.get(idx)
    }

    pub fn get_as<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>, JsonTableError> {
        let Some(v) = self.get(name) else { return Ok(None) };

        Ok(Some(T::deserialize(v).map_err(|e| JsonTableError::DeserializeTypedCell {
            r#type: type_name::<T>().to_string(),
            col: name.to_string(),
            row: self.row_idx,
            source: e,
        })?))
    }

    /// Like get(), but errors if not present
    pub fn require(&self, name: &str) -> Result<&'a Value, JsonTableError> {
        let idx = self
            .col_index(name)
            .ok_or_else(|| JsonTableError::UnknownColumn(name.to_string()))?;

        self.row.get(idx).ok_or_else(|| JsonTableError::MissingCell {
            col: name.to_string(),
            idx,
            row: self.row_idx,
        })
    }

    pub fn require_as<T: DeserializeOwned>(&self, name: &str) -> Result<T, JsonTableError> {
        let v = self.require(name)?;
        serde_json::from_value(v.clone()).map_err(|e| JsonTableError::DeserializeTypedCell {
            r#type: type_name::<T>().to_string(),
            col: name.to_string(),
            row: self.row_idx,
            source: e,
        })
    }
}

pub struct RecordsIter<'a> {
    schema: &'a [snowflake_api::FieldSchema],
    rows: std::slice::Iter<'a, Value>,
    row_idx: usize,
}

impl<'a> Iterator for RecordsIter<'a> {
    type Item = Result<RecordRef<'a>, JsonTableError>;

    fn next(&mut self) -> Option<Self::Item> {
        let v = self.rows.next()?;
        let idx = self.row_idx;
        self.row_idx += 1;

        match v.as_array() {
            Some(arr) => Some(Ok(RecordRef {
                schema: self.schema,
                row: arr.as_slice(),
                row_idx: idx,
            })),
            None => Some(Err(JsonTableError::RowNotAnArray {
                row: idx,
                got: json_kind(v),
            })),
        }
    }
}

/// Helper because serde_json::Value doesn't expose a simple "kind()".
fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub trait JsonResultExt {
    fn iter_records(&self) -> Result<RecordsIter<'_>, JsonTableError>;
}

impl JsonResultExt for snowflake_api::JsonResult {
    fn iter_records(&self) -> Result<RecordsIter<'_>, JsonTableError> {
        let rows = self
            .value
            .as_array()
            .ok_or(JsonTableError::NotAnArray(json_kind(&self.value)))?;

        Ok(RecordsIter {
            schema: &self.schema,
            rows: rows.iter(),
            row_idx: 0,
        })
    }
}
