/// Public native-shaped artifact shared by the adapter scenarios.
pub fn response() -> serde_json::Value {
    serde_json::from_str(include_str!("../assets/runtime-config.v1.json"))
        .expect("valid public runtime configuration fixture")
}
