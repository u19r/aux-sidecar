use super::*;

pub(super) fn normalize_path(path: &str) -> Option<String> {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    if !path.starts_with('/') || path.contains('#') {
        return None;
    }
    let segments = path.split('/').collect::<Vec<_>>();
    let mut normalized = String::with_capacity(path.len());
    for (index, segment) in segments.iter().enumerate() {
        if index > 0 {
            normalized.push('/');
        }
        if segment.is_empty() && index > 0 && index + 1 < segments.len() {
            return None;
        }
        normalized.push_str(segment);
    }
    Some(if normalized.is_empty() {
        "/".to_string()
    } else {
        normalized
    })
}

pub(super) fn normalize_template(template: &str) -> String {
    template
        .split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                "{}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub(super) fn match_template<'a>(
    operation: &'a CompiledOperation,
    path: &str,
) -> Option<RouteMatch<'a>> {
    let template_segments = operation.template.split('/').collect::<Vec<_>>();
    let path_segments = path.split('/').collect::<Vec<_>>();
    if template_segments.len() != path_segments.len() {
        return None;
    }
    let mut captures = BTreeMap::new();
    for (template, actual) in template_segments.iter().zip(path_segments) {
        if template.starts_with('{') && template.ends_with('}') {
            let name = template
                .strip_prefix('{')
                .and_then(|template| template.strip_suffix('}'))?;
            let parameter = operation
                .parameters
                .iter()
                .find(|parameter| parameter.name == name)?;
            if !valid_capture(actual, parameter.value_type) {
                return None;
            }
            captures.insert(name.to_string(), actual.to_string());
        } else if *template != actual {
            return None;
        }
    }
    Some(RouteMatch {
        operation,
        captures,
    })
}

fn valid_capture(value: &str, value_type: PathValueType) -> bool {
    match value_type {
        PathValueType::String => !value.is_empty() && !value.contains('/'),
        PathValueType::Integer => value.parse::<i64>().is_ok(),
        PathValueType::Uuid => is_uuid_literal(value),
    }
}

fn is_uuid_literal(value: &str) -> bool {
    let groups = [8, 4, 4, 4, 12];
    let mut parts = value.split('-');
    groups.iter().all(|length| {
        parts.next().is_some_and(|part| {
            part.len() == *length && part.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    }) && parts.next().is_none()
}

pub(super) fn number_at(path: &JsonPath, claims: &Value) -> Option<f64> {
    path.get(claims)?.as_f64()
}
