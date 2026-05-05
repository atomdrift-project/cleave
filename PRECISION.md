# Rule Precision Scoring

Precision is a metric used by cleave to measure how specific and constrained a detection rule is. It helps distinguish between broad, potentially noisy rules and highly targeted, high-confidence detections.

## Criticality Thresholds

Composite rules (those that combine other traits) must meet minimum precision thresholds to maintain their criticality level. If a rule's calculated precision is below the threshold, it is automatically downgraded:

- **HOSTILE**: Requires precision **>= 3.5**. If lower, it is downgraded to `SUSPICIOUS`.
- **SUSPICIOUS**: Requires precision **>= 2.0**. If lower, it is downgraded to `NOTABLE`.

## Calculation Algorithm

Precision is calculated recursively across the rule tree:

### Composite Rules
- **`all`**: Sum of precisions of all conditions in the list.
- **`any`**: Sum of the `N` weakest matching branches (where `N` is the `needs` value, default 1).
- **`none`**: Fixed bonus (0.3) + sum of precisions of all conditions in the list.
- **`unless`**: Fixed bonus (0.3) + precision of the weakest branch.

### Atomic Traits
Atomic traits start with a base precision of **1.0**. Precision is then added based on the specificity of the constraints:

#### Structural Constraints
- **File Type (`for`)**: +0.3 for each specific file type (excluding `all`).
- **Platform (`platforms`)**: +0.3 for each specific platform (excluding `all`).
- **Size (`size_min`, `size_max`)**: +0.3 each.

#### Pattern Matching (String/Symbol/Content)
Precision is proportional to the length of the pattern:
- **Exact/Substring**: `ceil(length / 5) * 0.3`
- **Regex**: `ceil(normalized_length / 5) * 0.3` (excluding escape characters)
- **Word**: `ceil((length + 2) / 5) * 0.3` (accounts for boundary anchors)

**Modifiers:**
- **Case-Insensitive**: Multiplies the pattern's precision by **0.25** (penalty for lower specificity).
- **Exclusion Patterns (`exclude_patterns`)**: Sum of precisions of each exclusion pattern.
- **Count Constraints (`count_min > 1`, `count_max`)**: +0.3 each.
- **Location Constraints (`section`, `offset`, etc.)**: +0.3 for each specific location filter.

#### Other Condition Types
- **YARA**: Based on rule name/namespace length + source complexity.
- **AST**: Based on node type, kind, and query complexity.
- **Syscall**: Based on name/number/arch specificity.
- **Binary Metrics**: Based on entropy, section ratios, etc.

## Guidelines for Authors

1. **Avoid Over-Downgrading**: If your `HOSTILE` composite rule is being downgraded to `SUSPICIOUS`, it likely needs more constraints (more sub-traits in `all`, or more specific patterns in the underlying atomic traits).
2. **Prefer Exact Matches**: Exact string matches provide higher precision than broad substrings or case-insensitive regexes.
3. **Use Structural Anchors**: Anchoring a search to a specific `section` or `offset` significantly boosts precision.
4. **Recursive Complexity**: Deeply nested composite rules can accumulate high precision, but ensure each level remains semantically meaningful.
5. **Word Boundaries**: Use `word: "..."` instead of `substr: "..."` when matching identifiers to avoid partial matches and gain a small precision boost.
6. **Tighten Cross-Source FPs with `scope:`**: When a composite rule fires on archive entries that just happen to coincide (e.g. one condition matches in entry A, another in entry B of the same zip), add `scope: leaf` (most strict — same analyzed unit), `scope: file` (same leaf-file, pooled with its decoded layers), or `scope: archive` (same archive entry, the looser-than-leaf option). Default `scope: outer` preserves today's behavior. Scope filtering happens before `near_bytes`/`near_lines`, so the two compose: scope picks the source bucket, proximity narrows within it.

## Limitations

- **Cycles**: To prevent infinite recursion, cycle detection returns a base precision of 1.0.
- **Inline Primitives**: Composite rules should only reference other traits. Inline primitives in composite rules are scored but will trigger validation errors.
