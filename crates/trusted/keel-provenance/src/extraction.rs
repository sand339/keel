//! Extraction schemas: operator-accepted, closed shapes for what a
//! quarantined model call may return about untrusted content (PLAN D82).
//!
//! The security bound is the schema's bandwidth, not the extracting model's
//! behaviour. A schema has no string type: every value is an enum member, a
//! bounded integer, a boolean, a path in the admitted tree, or an issue
//! number, alone or in a short list. "Force-push to main" cannot be spelled
//! in a schema of a few enums.

use serde_json::{Map, Value};
use std::{collections::BTreeMap, collections::BTreeSet, fmt};

const MAX_FIELDS: usize = 16;
const MAX_ENUM_VALUES: usize = 32;
const MAX_IDENTIFIER: usize = 32;
const MAX_LIST: u64 = 16;
const MAX_SCHEMA_BYTES: usize = 16 * 1024;
const MAX_SCHEMAS: usize = 16;
/// The largest bundle admission reads.
pub const MAX_BUNDLE_BYTES: usize = MAX_SCHEMA_BYTES * MAX_SCHEMAS;

/// One field's closed type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FieldType {
    /// One of a fixed set of short identifiers.
    Enum(BTreeSet<String>),
    /// An integer within inclusive bounds.
    Integer {
        /// Smallest allowed value.
        min: i64,
        /// Largest allowed value.
        max: i64,
    },
    /// `true` or `false`.
    Boolean,
    /// A path that names a file in the admitted `HEAD` tree.
    Path,
    /// An issue or pull request number on the admitted repository.
    Issue,
    /// Up to `max` distinct items of a non-list type.
    List {
        /// The item type.
        item: Box<FieldType>,
        /// The most items allowed.
        max: u64,
    },
}

/// An accepted extraction schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractionSchema {
    name: String,
    fields: BTreeMap<String, FieldType>,
}

/// Why a schema or an extraction was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractionError(String);

impl fmt::Display for ExtractionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ExtractionError {}

fn refuse(reason: impl Into<String>) -> ExtractionError {
    ExtractionError(reason.into())
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

impl FieldType {
    fn parse(value: &Value, nested: bool) -> Result<Self, ExtractionError> {
        let object = value
            .as_object()
            .filter(|object| object.len() == 1)
            .ok_or_else(|| refuse("a field type is one object with exactly one key"))?;
        let (kind, argument) = object
            .iter()
            .next()
            .ok_or_else(|| refuse("empty field type"))?;
        match kind.as_str() {
            "enum" => {
                let values = argument
                    .as_array()
                    .filter(|values| (1..=MAX_ENUM_VALUES).contains(&values.len()))
                    .ok_or_else(|| refuse("an enum lists 1 to 32 values"))?
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .filter(|value| identifier(value))
                            .map(str::to_owned)
                    })
                    .collect::<Option<BTreeSet<_>>>()
                    .ok_or_else(|| refuse("enum values are short lowercase identifiers"))?;
                Ok(Self::Enum(values))
            }
            "integer" => {
                let bound = |name: &str| argument.get(name).and_then(Value::as_i64);
                match (bound("min"), bound("max")) {
                    (Some(min), Some(max)) if min <= max => Ok(Self::Integer { min, max }),
                    _ => Err(refuse("an integer needs min <= max")),
                }
            }
            "boolean" if argument == &Value::Bool(true) => Ok(Self::Boolean),
            "path" if argument == &Value::Bool(true) => Ok(Self::Path),
            "issue" if argument == &Value::Bool(true) => Ok(Self::Issue),
            "list" if !nested => {
                let max = argument
                    .get("max")
                    .and_then(Value::as_u64)
                    .filter(|max| (1..=MAX_LIST).contains(max))
                    .ok_or_else(|| refuse("a list holds 1 to 16 items"))?;
                let item = Self::parse(
                    argument
                        .get("item")
                        .ok_or_else(|| refuse("a list names its item"))?,
                    true,
                )?;
                Ok(Self::List {
                    item: Box::new(item),
                    max,
                })
            }
            _ => Err(refuse(format!("unsupported field type `{kind}`"))),
        }
    }

    /// Upper bound on the bits one value of this type carries.
    fn bits(&self) -> f64 {
        match self {
            #[allow(clippy::cast_precision_loss)] // an enum has at most 32 values
            Self::Enum(values) => (values.len() as f64).log2(),
            #[allow(clippy::cast_precision_loss)]
            // bandwidth is an estimate, not a bound to the bit
            Self::Integer { min, max } => ((max.abs_diff(*min) as f64) + 1.0).log2(),
            Self::Boolean => 1.0,
            // A path names one of the admitted files and an issue one of a
            // repository's numbers; both are bounded by what already exists.
            Self::Path | Self::Issue => 20.0,
            #[allow(clippy::cast_precision_loss)] // at most 16
            Self::List { item, max } => item.bits() * (*max as f64),
        }
    }

    fn validate(
        &self,
        value: &Value,
        admitted: &BTreeSet<String>,
    ) -> Result<Value, ExtractionError> {
        match self {
            Self::Enum(values) => value
                .as_str()
                .filter(|value| values.contains(*value))
                .map(|value| Value::String(value.to_owned()))
                .ok_or_else(|| refuse("an enum value is not one of the schema's members")),
            Self::Integer { min, max } => value
                .as_i64()
                .filter(|value| (min..=max).contains(&value))
                .map(Value::from)
                .ok_or_else(|| refuse("an integer is outside the schema's bounds")),
            Self::Boolean => value
                .as_bool()
                .map(Value::Bool)
                .ok_or_else(|| refuse("a boolean is not true or false")),
            Self::Path => value
                .as_str()
                .filter(|path| admitted.contains(*path))
                .map(|path| Value::String(path.to_owned()))
                .ok_or_else(|| refuse("a path is not a file in the admitted tree")),
            Self::Issue => value
                .as_u64()
                .filter(|number| (1..=10_000_000).contains(number))
                .map(Value::from)
                .ok_or_else(|| refuse("an issue number is out of range")),
            Self::List { item, max } => {
                let values = value
                    .as_array()
                    .filter(|values| values.len() as u64 <= *max)
                    .ok_or_else(|| refuse("a list is too long or not a list"))?;
                let mut seen = BTreeSet::new();
                let mut out = Vec::with_capacity(values.len());
                for value in values {
                    let value = item.validate(value, admitted)?;
                    if seen.insert(value.to_string()) {
                        out.push(value);
                    }
                }
                Ok(Value::Array(out))
            }
        }
    }

    /// The JSON Schema the extracting model's structured output must follow.
    fn json_schema(&self) -> Value {
        match self {
            Self::Enum(values) => serde_json::json!({ "type": "string", "enum": values }),
            Self::Integer { min, max } => {
                serde_json::json!({ "type": "integer", "minimum": min, "maximum": max })
            }
            Self::Boolean => serde_json::json!({ "type": "boolean" }),
            Self::Path => {
                serde_json::json!({ "type": "string", "description": "a repository file path" })
            }
            Self::Issue => serde_json::json!({ "type": "integer", "minimum": 1 }),
            Self::List { item, max } => {
                serde_json::json!({ "type": "array", "items": item.json_schema(), "maxItems": max })
            }
        }
    }
}

impl ExtractionSchema {
    /// Parses one schema from its accepted JSON form.
    ///
    /// # Errors
    ///
    /// Returns an error for any shape outside the closed grammar: an unknown
    /// key or type, a non-identifier name, or too many fields or values.
    pub fn parse(text: &str) -> Result<Self, ExtractionError> {
        if text.len() > MAX_SCHEMA_BYTES {
            return Err(refuse("an extraction schema is larger than 16 KiB"));
        }
        let value: Value = serde_json::from_str(text).map_err(|error| refuse(error.to_string()))?;
        let object = value
            .as_object()
            .ok_or_else(|| refuse("a schema is an object"))?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "version" | "name" | "fields"))
        {
            return Err(refuse("a schema has only version, name, and fields"));
        }
        if object.get("version") != Some(&Value::from(1)) {
            return Err(refuse("a schema declares version 1"));
        }
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| identifier(name))
            .ok_or_else(|| refuse("a schema name is a short lowercase identifier"))?
            .to_owned();
        let fields = object
            .get("fields")
            .and_then(Value::as_object)
            .filter(|fields| (1..=MAX_FIELDS).contains(&fields.len()))
            .ok_or_else(|| refuse("a schema has 1 to 16 fields"))?
            .iter()
            .map(|(field, kind)| {
                if !identifier(field) {
                    return Err(refuse("a field name is a short lowercase identifier"));
                }
                Ok((field.clone(), FieldType::parse(kind, false)?))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(Self { name, fields })
    }

    /// The schema's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Upper bound on the bits one extraction can carry, shown at acceptance
    /// and admission so the operator sees what a hostile document could
    /// smuggle through it.
    #[must_use]
    pub fn bandwidth_bits(&self) -> u32 {
        let bits = self
            .fields
            .values()
            .map(FieldType::bits)
            .sum::<f64>()
            .ceil();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        // bounded by 16 fields of 16 items
        let bits = bits as u32;
        bits
    }

    /// The JSON Schema object for the forced structured-output tool.
    #[must_use]
    pub fn input_schema(&self) -> Value {
        let properties = self
            .fields
            .iter()
            .map(|(field, kind)| (field.clone(), kind.json_schema()))
            .collect::<Map<_, _>>();
        serde_json::json!({
            "type": "object",
            "properties": properties,
            "required": self.fields.keys().collect::<Vec<_>>(),
            "additionalProperties": false,
        })
    }

    /// Checks a model's structured output against the schema and returns its
    /// canonical form. `admitted` is the set of file paths in the admitted
    /// tree, against which `path` values are checked.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or extra field or any out-of-shape value.
    pub fn validate(
        &self,
        output: &Value,
        admitted: &BTreeSet<String>,
    ) -> Result<Value, ExtractionError> {
        let object = output
            .as_object()
            .ok_or_else(|| refuse("an extraction is an object"))?;
        if object.len() != self.fields.len()
            || object.keys().any(|key| !self.fields.contains_key(key))
        {
            return Err(refuse("an extraction has exactly the schema's fields"));
        }
        let mut canonical = Map::new();
        for (field, kind) in &self.fields {
            let value = object
                .get(field)
                .ok_or_else(|| refuse("a field is missing"))?;
            canonical.insert(field.clone(), kind.validate(value, admitted)?);
        }
        Ok(Value::Object(canonical))
    }
}

/// The accepted schemas a run admitted. Trusted admission checks the bundle's
/// digest before parsing it, as it does a policy bundle's.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SchemaRegistry {
    schemas: BTreeMap<String, ExtractionSchema>,
}

impl SchemaRegistry {
    /// Parses a bundle: a JSON array of schemas.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed schema or a duplicate name.
    pub fn from_bundle(text: &str) -> Result<Self, ExtractionError> {
        let values: Vec<Value> =
            serde_json::from_str(text).map_err(|error| refuse(error.to_string()))?;
        if values.is_empty() || values.len() > MAX_SCHEMAS {
            return Err(refuse("a bundle holds 1 to 16 schemas"));
        }
        let mut schemas = BTreeMap::new();
        for value in values {
            let schema = ExtractionSchema::parse(&value.to_string())?;
            if schemas.insert(schema.name.clone(), schema).is_some() {
                return Err(refuse("two schemas share a name"));
            }
        }
        Ok(Self { schemas })
    }

    /// The schema with this name, if the run admitted it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ExtractionSchema> {
        self.schemas.get(name)
    }

    /// One admission line per schema: name and bandwidth.
    #[must_use]
    pub fn describe(&self) -> Vec<String> {
        self.schemas
            .values()
            .map(|schema| format!("extract:{} ({} bits)", schema.name, schema.bandwidth_bits()))
            .collect()
    }
}

#[cfg(test)]
#[path = "../tests/support/extraction.rs"]
mod tests;
