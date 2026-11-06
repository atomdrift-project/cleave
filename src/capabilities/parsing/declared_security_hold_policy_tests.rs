use super::*;
use crate::composite_rules::Scope;

#[test]
fn confirmed_hold_is_independent_and_exemption_is_narrow() {
    let leg = [Condition::Trait {
        id: "metadata/package/dependencies/declaration::declared-dependency-security-held".into(),
    }];
    let id = "objectives/supply-chain/security-hold::declared-dependency-security-held";
    assert!(is_declared_dependency_security_hold_policy(
        id,
        Some(&leg),
        &[RuleFileType::PackageJson],
        Some(Scope::File)
    ));
    assert!(!is_declared_dependency_security_hold_policy(
        id,
        Some(&leg),
        &[RuleFileType::Registry],
        Some(Scope::File)
    ));
    assert!(!is_declared_dependency_security_hold_policy(
        id,
        Some(&leg),
        &[RuleFileType::PackageJson],
        None
    ));
    assert!(!is_declared_dependency_security_hold_policy(
        "other::id",
        Some(&leg),
        &[RuleFileType::PackageJson],
        Some(Scope::File)
    ));
    let unrelated = [Condition::Trait {
        id: "metadata/registry::version-removed".into(),
    }];
    assert!(!is_declared_dependency_security_hold_policy(
        id,
        Some(&unrelated),
        &[RuleFileType::PackageJson],
        Some(Scope::File)
    ));
}
