//! Exercise the public, cached API against the host's independent sysctl CLI.
#![cfg(target_os = "macos")]
#![allow(clippy::expect_used, clippy::panic)]

use std::process::Command;

fn sysctl(key: &str) -> Option<String> {
    let output = Command::new("/usr/sbin/sysctl")
        .args(["-n", key])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[test]
fn public_core_count_includes_every_performance_class_on_this_host() {
    let physical: usize = sysctl("hw.physicalcpu")
        .expect("run this integration test with permission to query host sysctls")
        .parse()
        .expect("physical core count");
    let mut efficiency = 0;
    if let Some(levels) = sysctl("hw.nperflevels") {
        for index in 0..levels.parse::<usize>().expect("performance class count") {
            let name = sysctl(&format!("hw.perflevel{index}.name")).expect("class name");
            let cores: usize = sysctl(&format!("hw.perflevel{index}.physicalcpu"))
                .expect("class count")
                .parse()
                .expect("physical class count");
            match name.as_str() {
                "Efficiency" => efficiency += cores,
                "Super" | "Performance" => {}
                other => panic!("new CPU class {other:?}: review performance-core policy"),
            }
        }
    }
    let expected = physical - efficiency;
    assert_eq!(sysmem::physical_cpu_count(), Some(expected));
    assert_eq!(sysmem::physical_cpu_count(), Some(expected), "cached query");
}
