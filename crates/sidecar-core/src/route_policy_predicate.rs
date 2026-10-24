use super::*;

pub(super) fn parse_predicate(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<ClaimPredicate, RoutePolicyError> {
    *nodes = nodes.saturating_add(1);
    if depth > MAX_PREDICATE_DEPTH || *nodes > MAX_PREDICATE_NODES {
        return Err(RoutePolicyError::PredicateInvalid(
            "predicate bounds exceeded".to_string(),
        ));
    }
    let object = value.as_object().ok_or_else(|| {
        RoutePolicyError::PredicateInvalid("predicate must be an object".to_string())
    })?;
    ensure_owned_fields(
        object,
        &[
            "all",
            "any",
            "not",
            "path",
            "exists",
            "equals",
            "in",
            "greater_than",
            "greater_than_or_equal",
            "less_than",
            "less_than_or_equal",
        ],
        "predicate",
    )
    .map_err(|_| RoutePolicyError::PredicateInvalid("unknown predicate field".to_string()))?;
    let operator_count = [
        "all",
        "any",
        "not",
        "exists",
        "equals",
        "in",
        "greater_than",
        "greater_than_or_equal",
        "less_than",
        "less_than_or_equal",
    ]
    .iter()
    .filter(|key| object.contains_key(**key))
    .count();
    if operator_count != 1 {
        return Err(RoutePolicyError::PredicateInvalid(
            "predicate must contain exactly one operator".to_string(),
        ));
    }
    if let Some(values) = object.get("all") {
        return Ok(ClaimPredicate::All(parse_predicate_array(
            values,
            depth + 1,
            nodes,
        )?));
    }
    if let Some(values) = object.get("any") {
        return Ok(ClaimPredicate::Any(parse_predicate_array(
            values,
            depth + 1,
            nodes,
        )?));
    }
    if let Some(value) = object.get("not") {
        return Ok(ClaimPredicate::Not(Box::new(parse_predicate(
            value,
            depth + 1,
            nodes,
        )?)));
    }
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| RoutePolicyError::PredicateInvalid("predicate path is required".to_string()))
        .and_then(JsonPath::parse)?;
    if let Some(exists) = object.get("exists") {
        if exists != &Value::Bool(true) {
            return Err(RoutePolicyError::PredicateInvalid(
                "exists predicate must be true; use not for absence".to_string(),
            ));
        }
        return Ok(ClaimPredicate::Exists { path });
    }
    if let Some(expected) = object.get("equals") {
        return Ok(ClaimPredicate::Equals {
            path,
            value: expected.clone(),
        });
    }
    if let Some(values) = object.get("in") {
        let values = values
            .as_array()
            .ok_or_else(|| RoutePolicyError::PredicateInvalid("in must be an array".to_string()))?
            .clone();
        return Ok(ClaimPredicate::In { path, values });
    }
    macro_rules! numeric {
        ($name:literal, $variant:ident) => {
            if let Some(value) = object.get($name).and_then(Value::as_f64) {
                return Ok(ClaimPredicate::$variant { path, value });
            }
        };
    }
    numeric!("greater_than", GreaterThan);
    numeric!("greater_than_or_equal", GreaterThanOrEqual);
    numeric!("less_than", LessThan);
    numeric!("less_than_or_equal", LessThanOrEqual);
    Err(RoutePolicyError::PredicateInvalid(
        "predicate operator is missing".to_string(),
    ))
}

fn parse_predicate_array(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<Vec<ClaimPredicate>, RoutePolicyError> {
    let values = value.as_array().ok_or_else(|| {
        RoutePolicyError::PredicateInvalid("predicate group must be an array".to_string())
    })?;
    if values.is_empty() {
        return Err(RoutePolicyError::PredicateInvalid(
            "predicate group cannot be empty".to_string(),
        ));
    }
    values
        .iter()
        .map(|value| parse_predicate(value, depth, nodes))
        .collect()
}

fn ensure_owned_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> Result<(), RoutePolicyError> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(RoutePolicyError::UnknownAuxExtension(format!(
                "{label}.{key}"
            )));
        }
    }
    Ok(())
}
