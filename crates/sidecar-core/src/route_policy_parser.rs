use super::*;

pub(super) fn parse_document(source: &[u8]) -> Result<Value, RoutePolicyError> {
    match serde_json::from_slice(source) {
        Ok(value) => Ok(value),
        Err(json_error) => serde_saphyr::from_slice(source).map_err(|yaml_error| {
            RoutePolicyError::Yaml(format!("{yaml_error}; JSON: {json_error}"))
        }),
    }
}

pub(super) fn resolve_refs(
    value: &mut Value,
    root: &Value,
    depth: usize,
    stack: &mut BTreeSet<String>,
) -> Result<(), RoutePolicyError> {
    if depth > MAX_REFERENCE_DEPTH {
        return Err(RoutePolicyError::ReferenceDepthExceeded(
            MAX_REFERENCE_DEPTH,
        ));
    }
    match value {
        Value::Object(object) => {
            if let Some(reference) = object
                .get("$ref")
                .and_then(Value::as_str)
                .map(str::to_string)
            {
                if !reference.starts_with("#/") {
                    return Err(RoutePolicyError::ExternalReference);
                }
                if !stack.insert(reference.clone()) {
                    return Err(RoutePolicyError::ReferenceCycle);
                }
                let target = reference
                    .trim_start_matches("#/")
                    .split('/')
                    .map(unescape_json_pointer)
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .try_fold(root, |current, key| current.get(key))
                    .ok_or_else(|| RoutePolicyError::InvalidField(reference.clone()))?
                    .clone();
                *value = target;
                resolve_refs(value, root, depth + 1, stack)?;
                stack.remove(&reference);
                return Ok(());
            }
            for child in object.values_mut() {
                resolve_refs(child, root, depth, stack)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                resolve_refs(child, root, depth, stack)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn compile_path_item(
    path: &str,
    path_value: &Value,
    operations: &mut Vec<CompiledOperation>,
) -> Result<(), RoutePolicyError> {
    if !path.starts_with('/') || path.contains('?') || path.contains('#') {
        return Err(RoutePolicyError::PathInvalid(path.to_string()));
    }
    let object = path_value
        .as_object()
        .ok_or_else(|| RoutePolicyError::PathInvalid(path.to_string()))?;
    ensure_aux_extensions(object, &[], path)?;
    let path_parameters = parse_parameters(object.get("parameters"), path)?;
    for method in METHODS {
        let Some(operation) = object.get(*method) else {
            continue;
        };
        let operation_object = operation
            .as_object()
            .ok_or_else(|| RoutePolicyError::InvalidField(format!("{path} {method}")))?;
        let label = format!("{method} {path}");
        ensure_aux_extensions(operation_object, &["x-aux-authn", "x-aux-authz"], &label)?;
        let authn = operation_object
            .get("x-aux-authn")
            .ok_or_else(|| RoutePolicyError::AuthnMissing(label.clone()))
            .and_then(|value| parse_authn(value, &label))?;
        let authz = operation_object
            .get("x-aux-authz")
            .map(|value| parse_authz(value, &label))
            .transpose()?;
        let parameters = merge_parameters(
            &path_parameters,
            parse_parameters(operation_object.get("parameters"), &label)?,
        )?;
        let operation_id = operation_object
            .get("operationId")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(authz) = authz.as_ref() {
            validate_authz_templates(authz, operation_id.as_deref(), &parameters, &label)?;
        }
        let capture_names = path
            .split('/')
            .filter_map(|segment| {
                if segment.contains(['{', '}'])
                    && !(segment.starts_with('{') && segment.ends_with('}'))
                {
                    return Some("");
                }
                segment
                    .strip_prefix('{')
                    .and_then(|segment| segment.strip_suffix('}'))
            })
            .collect::<Vec<_>>();
        if capture_names.len() > MAX_PATH_PARAMETERS || parameters.len() > MAX_PATH_PARAMETERS {
            return Err(RoutePolicyError::PathInvalid(path.to_string()));
        }
        let mut seen_captures = BTreeSet::new();
        if capture_names.iter().any(|name| {
            !seen_captures.insert(*name)
                || !parameters.iter().any(|parameter| parameter.name == *name)
        }) || parameters
            .iter()
            .any(|parameter| !seen_captures.contains(parameter.name.as_str()))
        {
            return Err(RoutePolicyError::PathInvalid(path.to_string()));
        }
        operations.push(CompiledOperation {
            method: (*method).to_string(),
            template: path.to_string(),
            operation_id,
            authn,
            authz,
            parameters,
        });
    }
    Ok(())
}

fn validate_authz_templates(
    authz: &RouteAuthz,
    operation_id: Option<&str>,
    parameters: &[PathParameter],
    label: &str,
) -> Result<(), RoutePolicyError> {
    let allowed = parameters
        .iter()
        .map(|parameter| parameter.name.as_str())
        .collect::<BTreeSet<_>>();
    for template in authz
        .decision
        .iter()
        .flat_map(|decision| decision.action.iter().chain(decision.resource.iter()))
    {
        let mut rest = template.as_str();
        while let Some((_, after_open)) = rest.split_once('{') {
            let Some((name, after_close)) = after_open.split_once('}') else {
                return Err(RoutePolicyError::TemplateInvalid(format!(
                    "{label}: unterminated template"
                )));
            };
            if name.is_empty()
                || (name == "operation_id" && operation_id.is_none())
                || (name != "operation_id" && name != "method" && !allowed.contains(name))
                || name.contains(['{', '}'])
            {
                return Err(RoutePolicyError::TemplateInvalid(format!(
                    "{label}: unsupported template capture {name:?}"
                )));
            }
            rest = after_close;
        }
        if rest.contains('}') {
            return Err(RoutePolicyError::TemplateInvalid(format!(
                "{label}: unmatched template delimiter"
            )));
        }
    }
    Ok(())
}

fn parse_authn(value: &Value, label: &str) -> Result<RouteAuthn, RoutePolicyError> {
    let object = value
        .as_object()
        .ok_or_else(|| RoutePolicyError::AuthnInvalid(label.to_string()))?;
    ensure_owned_fields(object, &["mode", "audiences"], label)
        .map_err(|_| RoutePolicyError::AuthnInvalid(label.to_string()))?;
    let mode = match object.get("mode").and_then(Value::as_str) {
        Some("public") => RouteAuthnMode::Public,
        Some("bearer") => RouteAuthnMode::Bearer,
        _ => return Err(RoutePolicyError::AuthnInvalid(label.to_string())),
    };
    let audiences = object
        .get("audiences")
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| RoutePolicyError::AuthnInvalid(label.to_string()))?
                .iter()
                .map(|value| {
                    let audience = value
                        .as_str()
                        .filter(|audience| !audience.trim().is_empty())
                        .ok_or_else(|| RoutePolicyError::AuthnInvalid(label.to_string()))?;
                    bounded_string(audience)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    if matches!(mode, RouteAuthnMode::Bearer) && audiences.is_empty() {
        return Err(RoutePolicyError::AuthnInvalid(label.to_string()));
    }
    if matches!(mode, RouteAuthnMode::Public) && !audiences.is_empty() {
        return Err(RoutePolicyError::AuthnInvalid(label.to_string()));
    }
    if audiences.iter().collect::<BTreeSet<_>>().len() != audiences.len() {
        return Err(RoutePolicyError::AuthnInvalid(label.to_string()));
    }
    Ok(RouteAuthn { mode, audiences })
}

fn parse_authz(value: &Value, label: &str) -> Result<RouteAuthz, RoutePolicyError> {
    let object = value
        .as_object()
        .ok_or_else(|| RoutePolicyError::AuthzInvalid(label.to_string()))?;
    ensure_owned_fields(object, &["required_scopes", "claims", "decision"], label)
        .map_err(|_| RoutePolicyError::AuthzInvalid(label.to_string()))?;
    let required_scopes = parse_string_array(object.get("required_scopes"))?;
    let claims = object
        .get("claims")
        .map(|value| {
            let mut nodes = 0;
            super::route_policy_predicate::parse_predicate(value, 0, &mut nodes)
        })
        .transpose()
        .map_err(|error| RoutePolicyError::AuthzInvalid(format!("{label}: {error}")))?;
    let decision = object
        .get("decision")
        .map(|value| {
            let decision = value
                .as_object()
                .ok_or_else(|| RoutePolicyError::AuthzInvalid(label.to_string()))?;
            ensure_owned_fields(decision, &["action", "resource"], label)
                .map_err(|_| RoutePolicyError::AuthzInvalid(label.to_string()))?;
            let action = decision
                .get("action")
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| RoutePolicyError::AuthzInvalid(label.to_string()))
                })
                .transpose()?;
            let resource = decision
                .get("resource")
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| RoutePolicyError::AuthzInvalid(label.to_string()))
                })
                .transpose()?;
            for value in action.iter().chain(resource.iter()) {
                bounded_string(value)?;
            }
            if action.is_none() && resource.is_none() {
                return Err(RoutePolicyError::AuthzInvalid(label.to_string()));
            }
            Ok(PdpTemplates {
                action: action.map(str::to_string),
                resource: resource.map(str::to_string),
            })
        })
        .transpose()?;
    Ok(RouteAuthz {
        required_scopes,
        claims,
        decision,
    })
}

pub(super) fn parse_fallback(
    value: &Value,
) -> Result<(RouteAuthn, Option<RouteAuthz>), RoutePolicyError> {
    let object = value
        .as_object()
        .ok_or_else(|| RoutePolicyError::InvalidField("x-aux-fallback".to_string()))?;
    ensure_owned_fields(object, &["x-aux-authn", "x-aux-authz"], "x-aux-fallback")?;
    let authn = object
        .get("x-aux-authn")
        .ok_or_else(|| RoutePolicyError::AuthnMissing("x-aux-fallback".to_string()))
        .and_then(|value| parse_authn(value, "x-aux-fallback"))?;
    let authz = object
        .get("x-aux-authz")
        .map(|value| parse_authz(value, "x-aux-fallback"))
        .transpose()?;
    Ok((authn, authz))
}

fn parse_string_array(value: Option<&Value>) -> Result<Vec<String>, RoutePolicyError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| RoutePolicyError::InvalidField("required_scopes".to_string()))?;
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let value = value
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| RoutePolicyError::InvalidField("required_scopes".to_string()))?;
        output.push(bounded_string(value)?);
    }
    let mut seen = BTreeSet::new();
    if output.iter().any(|item| !seen.insert(item.as_str())) {
        return Err(RoutePolicyError::InvalidField(
            "required_scopes".to_string(),
        ));
    }
    Ok(output)
}

fn parse_parameters(
    value: Option<&Value>,
    label: &str,
) -> Result<Vec<PathParameter>, RoutePolicyError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| RoutePolicyError::InvalidField(format!("{label} parameters")))?;
    values
        .iter()
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| RoutePolicyError::InvalidField(format!("{label} parameters")))?;
            let location = object
                .get("in")
                .and_then(Value::as_str)
                .ok_or_else(|| RoutePolicyError::InvalidField(format!("{label} parameter.in")))?;
            if location != "path" {
                return Ok(None);
            }
            if object.get("required") != Some(&Value::Bool(true)) {
                return Err(RoutePolicyError::InvalidField(format!(
                    "{label} path parameter required"
                )));
            }
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.trim().is_empty())
                .ok_or_else(|| RoutePolicyError::InvalidField(format!("{label} parameter.name")))?;
            let schema = object
                .get("schema")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    RoutePolicyError::InvalidField(format!("{label} parameter.schema"))
                })?;
            let value_type = match schema.get("format").and_then(Value::as_str) {
                Some("uuid") if schema.get("type").and_then(Value::as_str) == Some("string") => {
                    PathValueType::Uuid
                }
                Some(_) => {
                    return Err(RoutePolicyError::InvalidField(format!(
                        "{label} parameter.format"
                    )));
                }
                None => match schema.get("type").and_then(Value::as_str) {
                    Some("integer") => PathValueType::Integer,
                    Some("string") => PathValueType::String,
                    _ => {
                        return Err(RoutePolicyError::InvalidField(format!(
                            "{label} parameter.type"
                        )));
                    }
                },
            };
            Ok(Some(PathParameter {
                name: bounded_string(name)?,
                value_type,
            }))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|parameters| parameters.into_iter().flatten().collect())
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

pub(super) fn ensure_aux_extensions(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> Result<(), RoutePolicyError> {
    for key in object.keys().filter(|key| key.starts_with("x-aux-")) {
        if !allowed.contains(&key.as_str()) {
            return Err(RoutePolicyError::UnknownAuxExtension(format!(
                "{label}.{key}"
            )));
        }
    }
    Ok(())
}

fn unescape_json_pointer(value: &str) -> Result<String, RoutePolicyError> {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '~' {
            output.push(character);
            continue;
        }
        match chars.next() {
            Some('0') => output.push('~'),
            Some('1') => output.push('/'),
            _ => return Err(RoutePolicyError::InvalidField(value.to_string())),
        }
    }
    Ok(output)
}

fn merge_parameters(
    path: &[PathParameter],
    operation: Vec<PathParameter>,
) -> Result<Vec<PathParameter>, RoutePolicyError> {
    let mut merged = BTreeMap::new();
    for parameter in path.iter().chain(operation.iter()) {
        if let Some(existing) = merged.insert(parameter.name.clone(), parameter.clone())
            && existing != *parameter
        {
            return Err(RoutePolicyError::InvalidField(format!(
                "conflicting path parameter {}",
                parameter.name
            )));
        }
    }
    Ok(merged.into_values().collect())
}

fn bounded_string(value: &str) -> Result<String, RoutePolicyError> {
    if value.is_empty() || value.len() > MAX_PATTERN_BYTES || value.chars().any(char::is_control) {
        return Err(RoutePolicyError::PatternTooLarge(MAX_PATTERN_BYTES));
    }
    Ok(value.to_string())
}
