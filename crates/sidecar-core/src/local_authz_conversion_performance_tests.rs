use std::hint::black_box;

use authz_types::SubjectType;

use crate::performance_support_tests::{best_of_three, measure_allocations, percent_improvement};

#[test]
fn subject_type_parse_perf_loop_keeps_direct_enum_mapping() {
    let baseline = measure_allocations("baseline_subject_type_json_parse", || {
        for _ in 0..100_000 {
            black_box(
                serde_json::from_value::<SubjectType>(serde_json::Value::String("user".to_owned()))
                    .expect("subject type"),
            );
        }
    });
    let optimized = measure_allocations("optimized_subject_type_direct_mapping", || {
        for _ in 0..100_000 {
            black_box(crate::local_authz::subject_type_from_str("user").expect("subject type"));
        }
    });
    alloc_counter::emit_report(&baseline).expect("allocation report must be emitted");
    alloc_counter::emit_report(&optimized).expect("allocation report must be emitted");

    let baseline_cpu = best_of_three(|| {
        for _ in 0..100_000 {
            black_box(
                serde_json::from_value::<SubjectType>(serde_json::Value::String("user".to_owned()))
                    .expect("subject type"),
            );
        }
    });
    let optimized_cpu = best_of_three(|| {
        for _ in 0..100_000 {
            black_box(crate::local_authz::subject_type_from_str("user").expect("subject type"));
        }
    });
    println!(
        "subject_type_parse_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline_cpu.as_nanos(),
        optimized_cpu.as_nanos(),
        percent_improvement(baseline_cpu, optimized_cpu),
    );
    assert!(optimized.allocation_count < baseline.allocation_count);
    assert!(optimized_cpu < baseline_cpu);
}
