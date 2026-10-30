# Skills policy decision v2 contract

The Skills policy response uses `schema_version: "policy-decision/v2"`.
Policy-owned error codes are defined by the `SkillsPolicyErrorCode` enum in
`app/models/skills_policy.py`. Its independently versioned error-code contract
is `1.0.0` (`ERROR_CODE_CONTRACT_VERSION`). Every value uses the `policy.`
namespace so these extensions cannot collide with SDK error names.

| Code | Meaning |
| --- | --- |
| `policy.none` | Successful decision; no policy error. |
| `policy.disabled` | The opt-in policy integration is disabled. |
| `policy.kill_switch` | A policy or execution kill switch is active. |
| `policy.unapproved` | Required owner approval is absent. |
| `policy.mapping_mismatch` | The approved permission mapping does not match. |
| `policy.tenant_denied` | The tenant is not enabled. |
| `policy.workload_unavailable` | Workload identity configuration is incomplete. |
| `policy.transport_unsafe` | The required transport guarantee is absent. |
| `policy.audit_failure` | A durable Security Audit receipt could not be confirmed. |
| `policy.malformed` | The request or policy configuration is invalid. |
| `policy.workload_unauthorized` | The workload token is invalid or unauthorized. |
| `policy.unknown_action` | The action is outside the approved mapping. |
| `policy.unmapped_resource` | The resource is not a canonical skill version. |
| `policy.binding_mismatch` | A bound permission digest does not match. |
| `policy.stale` | Request freshness or authorization epoch validation failed. |
| `policy.unavailable` | A required policy or revocation dependency is unavailable. |
| `policy.denied` | The verified permissions do not authorize the action. |

Adding, removing, or renaming a code requires an error-code contract version
bump and an update to the pinned enum snapshot in
`tests/test_skills_policy_v2.py`. That test fails if the enum changes while the
contract version remains unchanged. The outer decision schema remains v2 unless
its request/response shape changes independently.
