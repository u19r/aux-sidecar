//! Startup-compiled OpenAPI route authorization for HTTP Sidecar deployments.
//!
//! The compiler deliberately owns the customer-facing `x-aux-*` contract. It
//! accepts standard OpenAPI fields without trying to model the entire OpenAPI
//! schema, but every Aux extension is parsed strictly and every route is
//! resolved before a server can accept traffic.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use thiserror::Error;

#[path = "route_policy_match.rs"]
mod route_policy_match;
#[path = "route_policy_parser.rs"]
mod route_policy_parser;
#[path = "route_policy_predicate.rs"]
mod route_policy_predicate;

pub const MAX_POLICY_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_OPERATIONS: usize = 2_000;
pub const MAX_REFERENCE_DEPTH: usize = 16;
pub const MAX_PATH_PARAMETERS: usize = 16;
pub const MAX_PREDICATE_DEPTH: usize = 8;
pub const MAX_PREDICATE_NODES: usize = 128;
pub const MAX_PATTERN_BYTES: usize = 1024;

const METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RoutePolicyError {
    #[error("route policy exceeds the 2 MiB source bound")]
    SourceTooLarge,
    #[error("route policy document is not a JSON or YAML object")]
    DocumentNotObject,
    #[error("route policy must contain an OpenAPI 3.1 paths object")]
    PathsMissing,
    #[error("route policy OpenAPI version must be 3.1")]
    OpenApiVersionInvalid,
    #[error("route policy contains an unsupported external reference")]
    ExternalReference,
    #[error("route policy reference depth exceeds {0}")]
    ReferenceDepthExceeded(usize),
    #[error("route policy reference cycle detected")]
    ReferenceCycle,
    #[error("route policy has more than {0} operations")]
    TooManyOperations(usize),
    #[error("route policy field {0:?} has the wrong shape")]
    InvalidField(String),
    #[error("unknown Aux extension {0:?}")]
    UnknownAuxExtension(String),
    #[error("operation {0:?} is missing x-aux-authn")]
    AuthnMissing(String),
    #[error("operation {0:?} has invalid x-aux-authn")]
    AuthnInvalid(String),
    #[error("operation {0:?} has invalid x-aux-authz")]
    AuthzInvalid(String),
    #[error("route policy path {0:?} is invalid")]
    PathInvalid(String),
    #[error("route policy contains ambiguous operations")]
    AmbiguousOperation,
    #[error("route policy predicate is invalid: {0}")]
    PredicateInvalid(String),
    #[error("route policy template is invalid: {0}")]
    TemplateInvalid(String),
    #[error("route policy pattern exceeds {0} bytes")]
    PatternTooLarge(usize),
    #[error("route policy YAML could not be parsed: {0}")]
    Yaml(String),
    #[error("route policy JSON could not be parsed: {0}")]
    Json(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAuthnMode {
    Public,
    Bearer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAuthn {
    pub mode: RouteAuthnMode,
    pub audiences: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RouteAuthz {
    pub required_scopes: Vec<String>,
    pub claims: Option<ClaimPredicate>,
    pub decision: Option<PdpTemplates>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PdpTemplates {
    pub action: Option<String>,
    pub resource: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClaimPredicate {
    All(Vec<Self>),
    Any(Vec<Self>),
    Not(Box<Self>),
    Exists { path: JsonPath },
    Equals { path: JsonPath, value: Value },
    In { path: JsonPath, values: Vec<Value> },
    GreaterThan { path: JsonPath, value: f64 },
    GreaterThanOrEqual { path: JsonPath, value: f64 },
    LessThan { path: JsonPath, value: f64 },
    LessThanOrEqual { path: JsonPath, value: f64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonPath {
    segments: Vec<String>,
}

impl JsonPath {
    pub fn parse(raw: &str) -> Result<Self, RoutePolicyError> {
        if raw.len() > MAX_PATTERN_BYTES || !raw.starts_with("$.") {
            return Err(RoutePolicyError::PredicateInvalid(
                "claim paths must start with $.".to_string(),
            ));
        }
        let segments = raw
            .strip_prefix("$.")
            .expect("validated claim path prefix")
            .split('.')
            .map(str::to_string)
            .collect::<Vec<_>>();
        if segments.is_empty()
            || segments
                .iter()
                .any(|segment| segment.is_empty() || segment.contains(['[', ']', '*']))
        {
            return Err(RoutePolicyError::PredicateInvalid(
                "claim path contains an unsupported segment".to_string(),
            ));
        }
        Ok(Self { segments })
    }

    fn get<'a>(&self, root: &'a Value) -> Option<&'a Value> {
        self.segments
            .iter()
            .try_fold(root, |value, segment| value.get(segment))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathParameter {
    pub name: String,
    pub value_type: PathValueType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathValueType {
    String,
    Integer,
    Uuid,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompiledOperation {
    pub method: String,
    pub template: String,
    pub operation_id: Option<String>,
    pub authn: RouteAuthn,
    pub authz: Option<RouteAuthz>,
    pub parameters: Vec<PathParameter>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RouteMatch<'a> {
    pub operation: &'a CompiledOperation,
    pub captures: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompiledRoutePolicy {
    operations: Vec<CompiledOperation>,
    exact: BTreeMap<(String, String), usize>,
    fallback: Option<(RouteAuthn, Option<RouteAuthz>)>,
}

impl CompiledRoutePolicy {
    pub fn compile(source: &[u8]) -> Result<Self, RoutePolicyError> {
        if source.len() > MAX_POLICY_BYTES {
            return Err(RoutePolicyError::SourceTooLarge);
        }
        let value = route_policy_parser::parse_document(source)?;
        Self::compile_value(value)
    }

    pub fn compile_value(mut root: Value) -> Result<Self, RoutePolicyError> {
        if !root.is_object() {
            return Err(RoutePolicyError::DocumentNotObject);
        }
        let reference_root = root.clone();
        route_policy_parser::resolve_refs(&mut root, &reference_root, 0, &mut BTreeSet::new())?;
        let object = root
            .as_object()
            .ok_or(RoutePolicyError::DocumentNotObject)?;
        route_policy_parser::ensure_aux_extensions(object, &["x-aux-fallback"], "document")?;
        // A complete document identifies itself as OpenAPI 3.1.  The compact
        // form intentionally omits the descriptive top-level fields and is
        // still governed by the same 3.1 path/operation contract.
        if let Some(version) = object.get("openapi")
            && version.as_str() != Some("3.1.0")
        {
            return Err(RoutePolicyError::OpenApiVersionInvalid);
        }
        let paths = object
            .get("paths")
            .and_then(Value::as_object)
            .ok_or(RoutePolicyError::PathsMissing)?;
        let fallback = object
            .get("x-aux-fallback")
            .map(route_policy_parser::parse_fallback)
            .transpose()?;
        let mut operations = Vec::new();
        for (path, path_value) in paths {
            route_policy_parser::compile_path_item(path, path_value, &mut operations)?;
        }
        if let Some((authn, authz)) = fallback.as_ref() {
            // Keep the fallback on the same compiled-operation path as every
            // concrete route.  Runtime code can therefore apply identical
            // authentication and authorization checks after a miss without
            // carrying a second policy representation.
            operations.push(CompiledOperation {
                method: "*".to_string(),
                template: "*".to_string(),
                operation_id: None,
                authn: authn.clone(),
                authz: authz.clone(),
                parameters: Vec::new(),
            });
        }
        if operations.len() > MAX_OPERATIONS {
            return Err(RoutePolicyError::TooManyOperations(MAX_OPERATIONS));
        }
        let mut exact = BTreeMap::new();
        let mut template_shapes = BTreeSet::new();
        for (index, operation) in operations.iter().enumerate() {
            if operation.method == "*" {
                continue;
            }
            if operation.parameters.is_empty() && operation.template.contains('{') {
                return Err(RoutePolicyError::PathInvalid(operation.template.clone()));
            }
            if !operation.template.contains('{') {
                if exact
                    .insert(
                        (operation.method.clone(), operation.template.clone()),
                        index,
                    )
                    .is_some()
                {
                    return Err(RoutePolicyError::AmbiguousOperation);
                }
            } else {
                let shape = format!(
                    "{} {}",
                    operation.method,
                    route_policy_match::normalize_template(&operation.template)
                );
                if !template_shapes.insert(shape) {
                    return Err(RoutePolicyError::AmbiguousOperation);
                }
            }
        }
        Ok(Self {
            operations,
            exact,
            fallback,
        })
    }

    #[must_use]
    pub fn operations(&self) -> &[CompiledOperation] {
        &self.operations
    }

    #[must_use]
    pub fn fallback(&self) -> Option<(&RouteAuthn, Option<&RouteAuthz>)> {
        self.fallback
            .as_ref()
            .map(|(authn, authz)| (authn, authz.as_ref()))
    }

    pub fn match_route<'a>(&'a self, method: &str, path: &str) -> Option<RouteMatch<'a>> {
        let method = method.to_ascii_lowercase();
        let path = route_policy_match::normalize_path(path)?;
        if let Some(index) = self.exact.get(&(method.clone(), path.clone())) {
            return Some(RouteMatch {
                operation: &self.operations[*index],
                captures: BTreeMap::new(),
            });
        }
        self.operations
            .iter()
            .filter(|operation| operation.method == method && operation.template.contains('{'))
            .find_map(|operation| route_policy_match::match_template(operation, &path))
            .or_else(|| {
                self.operations
                    .iter()
                    .find(|operation| operation.method == "*" && operation.template == "*")
                    .map(|operation| RouteMatch {
                        operation,
                        captures: BTreeMap::new(),
                    })
            })
    }

    #[must_use]
    pub fn fallback_match(&self) -> Option<RouteMatch<'_>> {
        self.operations
            .iter()
            .find(|operation| operation.method == "*" && operation.template == "*")
            .map(|operation| RouteMatch {
                operation,
                captures: BTreeMap::new(),
            })
    }
}

impl ClaimPredicate {
    pub fn evaluate(&self, claims: &Value) -> bool {
        match self {
            Self::All(predicates) => predicates
                .iter()
                .all(|predicate| predicate.evaluate(claims)),
            Self::Any(predicates) => predicates
                .iter()
                .any(|predicate| predicate.evaluate(claims)),
            Self::Not(predicate) => !predicate.evaluate(claims),
            Self::Exists { path } => path.get(claims).is_some(),
            Self::Equals { path, value } => path.get(claims) == Some(value),
            Self::In { path, values } => path
                .get(claims)
                .is_some_and(|actual| values.iter().any(|value| value == actual)),
            Self::GreaterThan { path, value } => {
                route_policy_match::number_at(path, claims).is_some_and(|actual| actual > *value)
            }
            Self::GreaterThanOrEqual { path, value } => {
                route_policy_match::number_at(path, claims).is_some_and(|actual| actual >= *value)
            }
            Self::LessThan { path, value } => {
                route_policy_match::number_at(path, claims).is_some_and(|actual| actual < *value)
            }
            Self::LessThanOrEqual { path, value } => {
                route_policy_match::number_at(path, claims).is_some_and(|actual| actual <= *value)
            }
        }
    }
}

#[cfg(test)]
#[path = "route_policy_tests.rs"]
mod route_policy_tests;

#[cfg(test)]
#[path = "route_policy_performance_tests.rs"]
mod route_policy_performance_tests;
