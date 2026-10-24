use crate::{
    REGISTRY_PULL_TOTAL, RegistryMetricDimensions, RegistryMetricIngestRequest,
    RegistryPrometheusRollupLabels, RegistryRateLimitAction,
};

#[test]
fn registry_metric_ingest_given_repository_user_org_dimensions_then_validates() {
    let request = RegistryMetricIngestRequest {
        metric_name: REGISTRY_PULL_TOTAL.to_string(),
        value: 1,
        dimensions: registry_dimensions(),
    };

    request
        .validate()
        .expect("registry metrics request should validate");
}

#[test]
fn registry_metric_ingest_given_unknown_metric_name_then_rejects() {
    let request = RegistryMetricIngestRequest {
        metric_name: "aux_registry_unknown_total".to_string(),
        value: 1,
        dimensions: registry_dimensions(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn registry_prometheus_rollup_labels_exclude_high_cardinality_fields() {
    let labels = RegistryPrometheusRollupLabels {
        environment: "test".to_string(),
        action: RegistryRateLimitAction::Pull,
        status_class: "2xx".to_string(),
    };

    labels
        .validate()
        .expect("bounded rollup labels should validate");
}

fn registry_dimensions() -> RegistryMetricDimensions {
    RegistryMetricDimensions {
        repository: "team/service-api".to_string(),
        user_id: "user_123".to_string(),
        organization_id: "org_acme".to_string(),
        action: RegistryRateLimitAction::Pull,
        status_class: "2xx".to_string(),
        bytes: Some(4096),
    }
}
