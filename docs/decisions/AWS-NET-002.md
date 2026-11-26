# AWS-NET-002 — Block Unrestricted RDP Ingress

**Status:** Implemented and validated  
**Phase:** Phase 2 — Network Policies  
**Policy ID:** `AWS-NET-002`  
**Severity:** `HIGH`  
**Category:** `NETWORK`

---

## 1. Policy Objective

Prevent AWS security group ingress rules from exposing Remote Desktop Protocol (RDP), TCP port `3389`, to unrestricted public IPv4 or IPv6 sources.

The policy evaluates Terraform plan JSON before infrastructure deployment.

It supports three Terraform resource types:

- `aws_security_group` — inline ingress rules.
- `aws_vpc_security_group_ingress_rule` — modern standalone ingress rules.
- `aws_security_group_rule` — legacy standalone ingress rules.

Both unrestricted IPv4 (`0.0.0.0/0`) and IPv6 (`::/0`) sources are prohibited.

## 2. Terraform Schema Discovery

I reused the AWS provider schema discovery process established during AWS-NET-001 and validated the resource representations against actual Terraform plan JSON generated using AWS provider version `6.73.0`.

### 2.1 Resource representations

| Resource | Protocol | Ports | IPv4 source | IPv6 source |
|---|---|---|---|---|
| `aws_security_group` | `ingress[].protocol` | `ingress[].from_port`, `to_port` | `ingress[].cidr_blocks` | `ingress[].ipv6_cidr_blocks` |
| `aws_vpc_security_group_ingress_rule` | `ip_protocol` | `from_port`, `to_port` | `cidr_ipv4` | `cidr_ipv6` |
| `aws_security_group_rule` | `protocol` | `from_port`, `to_port` | `cidr_blocks` | `ipv6_cidr_blocks` |

### 2.2 Important schema findings

- Inline ingress rules are nested inside the `ingress` collection.
- Modern standalone rules represent one ingress rule per resource.
- Legacy standalone rules use a `type` attribute to distinguish ingress from egress.
- Security-relevant attributes can be unknown during Terraform planning.
- Each resource representation requires its own attribute evaluation.

**Decision:** Reuse the established multi-resource evaluation architecture while handling RDP-specific protocol and port conditions.

## 3. RDP Detection Logic

The policy identifies RDP exposure using protocol and port information.

Supported protocol representations:

- `tcp`
- `6` — numeric TCP protocol identifier.
- `-1` — all protocols, which includes RDP.

For TCP rules, port 3389 is considered exposed when:

`from_port <= 3389` and `to_port >= 3389`

This detects port ranges containing RDP, not just rules explicitly configured for port 3389.

All-protocol rules are evaluated as potential RDP exposure regardless of their port attributes.

**Decision:** A rule violates the policy when it permits TCP port 3389, or all protocols, from an unrestricted public source.

## 4. Change Evaluation

Terraform plan JSON includes resource change actions.

The policy evaluates:

- `create`
- `update`
- `delete` followed by `create` (replacement)
- `create` followed by `delete` (replacement)

Delete-only and no-op changes are excluded.

Evaluation uses the planned `change.after` representation rather than the previous resource configuration.

Inline ingress rules are evaluated independently so that one restricted rule does not conceal another unrestricted rule.

**Decision:** Evaluate planned active configurations and exclude changes that do not introduce or retain the relevant ingress configuration.

## 5. IPv4 and IPv6 Enforcement

Both unrestricted source ranges are independently prohibited.

| Address | Meaning | Result |
|---|---|---|
| `0.0.0.0/0` | All IPv4 addresses | Deny |
| `::/0` | All IPv6 addresses | Deny |

Restricted CIDRs are accepted by this policy.

**Decision:** Evaluate IPv4 and IPv6 independently. Both address families must be covered to avoid leaving an unrestricted exposure path.

## 6. Unknown-Value Handling

Terraform may not determine all resource attributes during planning.

These unresolved values are represented through `change.after_unknown`.

Ignoring unknown security-relevant values could allow potentially unrestricted RDP ingress to pass policy evaluation.

I implemented conservative unknown-value handling.

### 6.1 Unknown-value representation

| Resource | Unknown-value representation |
|---|---|
| Inline security group | Nested objects in `after_unknown.ingress`, aligned by rule index |
| Modern standalone rule | Boolean flags for individual attributes |
| Legacy standalone rule | Boolean flags for individual attributes and CIDR collections |

### 6.2 Security-relevant attributes

The policy evaluates:

- Protocol (`protocol` or `ip_protocol`)
- Starting port (`from_port`)
- Ending port (`to_port`)
- IPv4 source CIDR
- IPv6 source CIDR

### 6.3 Unknown-value decisions

The policy distinguishes confirmed violations from indeterminate compliance.

| Condition | Result |
|---|---|
| Unknown protocol | Indeterminate violation |
| Unknown TCP port range | Indeterminate violation |
| Known TCP range excludes 3389 | Pass |
| Matching TCP range with unknown CIDR | Indeterminate violation |
| All-protocol rule with unknown CIDR | Indeterminate violation |
| Known public CIDR and matching RDP protocol/port | Confirmed violation |
| Known restricted CIDR | Pass |
| Unknown unrelated attribute | Pass |

A confirmed public exposure takes precedence over an indeterminate result when both are encountered.

The policy does not report an unknown value as a confirmed public exposure.

**Decision:** Fail closed when unresolved security-relevant values could change the RDP compliance decision, without generating false positives for unrelated unknown attributes.

### 6.4 Inline rule alignment

Inline security group rules require special handling.

The `after_unknown.ingress` collection corresponds to `after.ingress` by index.

Each planned ingress rule is evaluated alongside its corresponding unknown-value metadata.

This prevents unknown attributes from one ingress rule from being incorrectly associated with another.

## 7. Violation Contract

Every violation follows the project's canonical seven-field contract.

| Field | Purpose |
|---|---|
| `policy_id` | Unique policy identifier |
| `title` | Human-readable policy title |
| `severity` | Risk classification |
| `category` | Policy category |
| `resource` | Terraform resource address |
| `message` | Explanation of the violation |
| `remediation` | Recommended corrective action |

For AWS-NET-002:

- Policy ID: `AWS-NET-002`
- Title: `Block Unrestricted RDP Ingress`
- Severity: `HIGH`
- Category: `NETWORK`

Confirmed violations identify the public IPv4 or IPv6 exposure.

Indeterminate violations explain that compliance cannot be determined because a security-relevant attribute is unknown.

Both outcomes use the same seven-field structure.

**Decision:** Preserve the canonical violation contract across confirmed and indeterminate outcomes.

## 8. Conftest Integration

Conftest expects a string-valued `msg` field in its `deny` results.

The implementation separates canonical policy output from Conftest-specific output.

- `violations` produces canonical seven-field violation objects.
- `deny` adds `msg` using `object.union()` without modifying the canonical violation structure.

**Decision:** Keep the canonical policy contract independent of Conftest output requirements.

## 9. Testing Strategy

Testing was performed at two levels.

### 9.1 Unit testing

File:

`policies/network/tests/aws_net_002_test.rego`

The test suite covers:

- Public IPv4 RDP detection.
- Public IPv6 RDP detection.
- All three supported Terraform resource types.
- Restricted CIDR acceptance.
- TCP ranges containing port 3389.
- TCP ranges excluding port 3389.
- All-protocol rules.
- Numeric TCP protocol.
- Delete-only exclusion.
- Create and update evaluation.
- Replacement action evaluation.
- Independent inline ingress rule evaluation.
- Seven-field violation contract.
- Conftest `deny` adapter.
- Unknown protocol, ports, and CIDRs.
- Unrelated unknown attributes.

**Final combined result:**

`50 tests, 50 passed, 0 warnings, 0 failures, 0 exceptions, 0 skipped`

The combined suite includes NET-001 and NET-002 tests.

### 9.2 Positive integration testing

I used the actual Terraform plan generated from:

`examples/phase-2-schema-lab/`

The initial configuration intentionally contained six unrestricted RDP exposures:

- Inline: IPv4 and IPv6.
- Modern standalone: IPv4 and IPv6.
- Legacy standalone: IPv4 and IPv6.

GitHub Actions run:

`45843014147`

The workflow captured Conftest's expected denial output and verified that exactly six `AWS-NET-002` violations were reported.

**Result:** All six unrestricted RDP exposures were detected.

GitHub Actions completed successfully because the workflow explicitly verified the expected policy denials.

### 9.3 Negative integration testing

I changed all six RDP source CIDRs to restricted documentation-range addresses:

- IPv4: `203.0.113.10/32`
- IPv6: `2001:db8::10/128`

The RDP protocol and port configurations remained unchanged.

I restored normal Conftest enforcement in the GitHub Actions workflow:

`conftest test tfplan.json --policy ../../policies/network`

GitHub Actions run:

`45891875248`

The workflow completed successfully with normal Conftest enforcement.

**Result:** The compliant Terraform plan passed without policy violations.

## 10. Enforcement Decisions

The following enforcement decisions apply:

1. All violations block CI, regardless of severity.
2. Severity communicates risk; it does not determine whether a violation blocks deployment.
3. Unknown security-relevant values are handled conservatively.
4. Confirmed violations and indeterminate compliance use distinct messages.
5. Restricted CIDRs are accepted by this policy.
6. Egress rules are outside this policy's scope.
7. Delete-only and no-op changes are excluded.
8. Replacement configurations are evaluated.
9. Policy output must remain deterministic and follow the canonical violation contract.

## 11. Scope and Limitations

AWS-NET-002 addresses unrestricted RDP ingress through the three supported Terraform security group resource types.

It does not evaluate:

- Other exposed ports.
- Other network access mechanisms.
- RDP exposure through resources outside its supported resource types.
- Whether a restricted CIDR is operationally approved or belongs to a trusted organization network.

Restricted CIDRs are considered compliant by this policy even though organizational approval of those ranges is outside its scope.

Those concerns require separate controls or policies.

## 12. Final Validation and Completion

| Validation | Result |
|---|---|
| OPA syntax validation | Passed |
| Combined unit tests | 50/50 passed |
| Positive integration test | Six RDP violations detected |
| Negative integration test | Compliant plan passed |
| Canonical violation contract | Verified |
| GitHub Actions execution | Both integration runs successful |

**Final status: Implemented and validated.**

AWS-NET-002 extends the network policy engine's existing implementation pattern while introducing RDP-specific protocol, port-range, and unknown-value evaluation.

---

**Next policy:** `AWS-NET-003` — Block unrestricted public database ingress.