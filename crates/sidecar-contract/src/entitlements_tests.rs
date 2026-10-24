use serde_json::json;

use crate::{
    EntitlementDecision, EntitlementEvaluateRequest, EntitlementEvaluateResponse,
    EntitlementEvaluationResult, EntitlementUsedEntitlement,
};

#[test]
fn entitlement_evaluate_request_matches_auxfn_public_contract_shape() {
    let request: EntitlementEvaluateRequest = serde_json::from_value(json!({
        "org_id": "org_canary",
        "keys": ["feature.sidecar"]
    }))
    .expect("entitlement evaluate request");

    assert_eq!(request.org_id, "org_canary");

    let request_json = serde_json::to_value(request).expect("entitlement request json");
    assert_eq!(request_json["org_id"], "org_canary");
    assert_eq!(request_json["keys"][0], "feature.sidecar");
}

#[test]
fn entitlement_request_given_too_many_keys_then_rejects_before_materialization() {
    let value = serde_json::json!({
        "org_id": "org_canary",
        "keys": (0..101)
            .map(|index| format!("feature.{index}"))
            .collect::<Vec<_>>()
    });

    assert!(serde_json::from_value::<EntitlementEvaluateRequest>(value).is_err());
}

#[test]
fn entitlement_request_given_duplicate_or_malformed_key_then_rejects() {
    let mut request = EntitlementEvaluateRequest {
        org_id: "org_canary".to_string(),
        at_time: None,
        keys: Some(vec![
            "feature.enabled".to_string(),
            "feature.enabled".to_string(),
        ]),
    };
    assert!(request.validate().is_err());

    request.keys = Some(vec!["feature#enabled".to_string()]);
    assert!(request.validate().is_err());
}

#[test]
fn entitlement_response_given_surplus_items_then_rejects_for_request() {
    let request = EntitlementEvaluateRequest {
        org_id: "org_canary".to_string(),
        at_time: None,
        keys: Some(vec!["feature.enabled".to_string()]),
    };
    let response = EntitlementEvaluateResponse {
        items: vec![
            entitlement_result("feature.enabled"),
            entitlement_result("feature.other"),
        ],
    };

    assert!(response.validate_for_request(&request).is_err());
}

#[test]
fn entitlement_response_given_too_many_items_then_rejects_before_materialization() {
    let value = serde_json::json!({
        "items": (0..16_385)
            .map(|index| {
                serde_json::json!({
                    "key": format!("feature.{index}"),
                    "decision": {"decision": "not_entitled"},
                    "used_entitlements": []
                })
            })
            .collect::<Vec<_>>()
    });

    assert!(serde_json::from_value::<EntitlementEvaluateResponse>(value).is_err());
}

#[test]
fn entitlement_result_given_too_many_used_entitlements_then_rejects_before_materialization() {
    let value = serde_json::json!({
        "items": [{
            "key": "feature.enabled",
            "decision": {"decision": "granted", "value": true},
            "used_entitlements": (0..101)
                .map(|index| serde_json::json!({
                    "entitlement_id": format!("entitlement-{index}"),
                    "operator": "equals",
                    "value": true
                }))
                .collect::<Vec<_>>()
        }]
    });

    assert!(serde_json::from_value::<EntitlementEvaluateResponse>(value).is_err());
}

fn entitlement_result(key: &str) -> EntitlementEvaluationResult {
    EntitlementEvaluationResult {
        key: key.to_string(),
        decision: EntitlementDecision::NotEntitled,
        used_entitlements: Vec::<EntitlementUsedEntitlement>::new(),
    }
}
