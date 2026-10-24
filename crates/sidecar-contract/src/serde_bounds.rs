use std::marker::PhantomData;

use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};

use crate::constants::CONTRACT_MAX_STRING_BYTES;

pub(crate) fn deserialize_bounded_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where D: Deserializer<'de> {
    deserialize_string_with_limit(deserializer, CONTRACT_MAX_STRING_BYTES, false)
}

pub(crate) fn deserialize_non_empty_bounded_string<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where D: Deserializer<'de> {
    deserialize_string_with_limit(deserializer, CONTRACT_MAX_STRING_BYTES, true)
}

pub(crate) fn deserialize_non_empty_string_with_limit<'de, D>(
    deserializer: D,
    max: usize,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_with_limit(deserializer, max, true)
}

pub(crate) fn deserialize_optional_bounded_string<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where D: Deserializer<'de> {
    deserialize_optional_string(deserializer, false)
}

pub(crate) fn deserialize_optional_non_empty_bounded_string<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where D: Deserializer<'de> {
    deserialize_optional_string(deserializer, true)
}

pub(crate) fn deserialize_bounded_vec<'de, D, T>(
    deserializer: D,
    max: usize,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor {
        max,
        marker: PhantomData,
    })
}

pub(crate) fn deserialize_bounded_string_vec<'de, D>(
    deserializer: D,
    max: usize,
) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedStringVecVisitor { max })
}

pub(crate) fn deserialize_optional_bounded_string_vec<'de, D>(
    deserializer: D,
    max: usize,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_option(OptionalStringVecVisitor { max })
}

pub(crate) fn deserialize_bounded_string_map<'de, D>(
    deserializer: D,
    max: usize,
) -> Result<std::collections::BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(BoundedStringMapVisitor { max })
}

pub(crate) fn deserialize_optional_bounded_u64<'de, D>(
    deserializer: D,
    max: u64,
) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_option(OptionalU64Visitor { max })
}

fn deserialize_optional_string<'de, D>(
    deserializer: D,
    require_non_empty: bool,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_option(OptionalStringVisitor { require_non_empty })
}

fn deserialize_string_with_limit<'de, D>(
    deserializer: D,
    max: usize,
    require_non_empty: bool,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_string(BoundedStringVisitor {
        max,
        require_non_empty,
    })
}

struct BoundedStringVisitor {
    max: usize,
    require_non_empty: bool,
}

impl<'de> Visitor<'de> for BoundedStringVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where E: de::Error {
        validate_string::<E>(value, self.max, self.require_non_empty)?;
        Ok(value.to_owned())
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where E: de::Error {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where E: de::Error {
        validate_string::<E>(&value, self.max, self.require_non_empty)?;
        Ok(value)
    }
}

struct OptionalStringVisitor {
    require_non_empty: bool,
}

impl<'de> Visitor<'de> for OptionalStringVisitor {
    type Value = Option<String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an optional bounded string")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where E: de::Error {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where D: Deserializer<'de> {
        deserializer
            .deserialize_string(BoundedStringVisitor {
                max: CONTRACT_MAX_STRING_BYTES,
                require_non_empty: self.require_non_empty,
            })
            .map(Some)
    }
}

struct BoundedVecVisitor<T> {
    max: usize,
    marker: PhantomData<T>,
}

impl<'de, T> Visitor<'de> for BoundedVecVisitor<T>
where T: Deserialize<'de>
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded sequence")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where A: SeqAccess<'de> {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or_default().min(self.max));
        while values.len() < self.max {
            let Some(value) = sequence.next_element()? else {
                return Ok(values);
            };
            values.push(value);
        }
        reject_extra_sequence_element(&mut sequence, self.max).map(|()| values)
    }
}

struct BoundedStringVecVisitor {
    max: usize,
}

impl<'de> Visitor<'de> for BoundedStringVecVisitor {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded sequence of strings")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where A: SeqAccess<'de> {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or_default().min(self.max));
        while values.len() < self.max {
            let Some(value) = sequence.next_element::<BoundedString>()? else {
                return Ok(values);
            };
            values.push(value.0);
        }
        reject_extra_sequence_element(&mut sequence, self.max).map(|()| values)
    }
}

struct OptionalStringVecVisitor {
    max: usize,
}

impl<'de> Visitor<'de> for OptionalStringVecVisitor {
    type Value = Option<Vec<String>>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an optional bounded sequence of strings")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where E: de::Error {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where D: Deserializer<'de> {
        deserialize_bounded_string_vec(deserializer, self.max).map(Some)
    }
}

struct BoundedStringMapVisitor {
    max: usize,
}

impl<'de> Visitor<'de> for BoundedStringMapVisitor {
    type Value = std::collections::BTreeMap<String, String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded string map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where A: MapAccess<'de> {
        let mut values = std::collections::BTreeMap::new();
        while values.len() < self.max {
            let Some((key, value)) = map.next_entry::<BoundedString, BoundedString>()? else {
                return Ok(values);
            };
            values.insert(key.0, value.0);
        }
        if map
            .next_entry::<de::IgnoredAny, de::IgnoredAny>()?
            .is_some()
        {
            return Err(de::Error::custom(collection_limit_message(self.max)));
        }
        Ok(values)
    }
}

struct OptionalU64Visitor {
    max: u64,
}

impl<'de> Visitor<'de> for OptionalU64Visitor {
    type Value = Option<u64>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an optional bounded unsigned integer")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where E: de::Error {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where D: Deserializer<'de> {
        let value = u64::deserialize(deserializer)?;
        (value <= self.max)
            .then_some(Some(value))
            .ok_or_else(|| de::Error::custom(format!("value exceeds maximum of {}", self.max)))
    }
}

struct BoundedString(String);

impl<'de> Deserialize<'de> for BoundedString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        deserialize_non_empty_bounded_string(deserializer).map(Self)
    }
}

fn reject_extra_sequence_element<'de, A>(sequence: &mut A, max: usize) -> Result<(), A::Error>
where A: SeqAccess<'de> {
    if sequence.next_element::<de::IgnoredAny>()?.is_some() {
        return Err(de::Error::custom(collection_limit_message(max)));
    }
    Ok(())
}

fn validate_string<E>(value: &str, max: usize, require_non_empty: bool) -> Result<(), E>
where E: de::Error {
    if value.len() > max {
        return Err(de::Error::custom(string_limit_message()));
    }
    if require_non_empty && value.trim().is_empty() {
        return Err(de::Error::custom("string must not be empty"));
    }
    Ok(())
}

const fn string_limit_message() -> &'static str {
    "string exceeds the contract byte bound"
}

fn collection_limit_message(max: usize) -> String {
    format!("collection exceeds maximum of {max} items")
}
