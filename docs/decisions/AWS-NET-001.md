# AWS-NET-001 — Block Unrestricted SSH Ingress

**Status:** Implemented and validated  
**Phase:** Phase 2 — Network Policies  
**Policy ID:** `AWS-NET-001`  
**Severity:** `HIGH`  
**Category:** `NETWORK`

---

## 1. Policy Objective

Prevent AWS security group ingress rules from exposing SSH (TCP port 22) to unrestricted public IPv4 or IPv6 sources.

The policy evaluates Terraform plan JSON before infrastructure deployment.

It supports three Terraform resource types:

- `aws_security_group` - inline ingress rules.
- `aws_vpc_security_group_ingress_rule` - modern standalone ingress rules.
- `aws_security_group_rule` - legacy standalone ingress rules.

Both IPv4 (`0.0.0.0/0`) and IPv6 (`::/0`) unrestricted sources are prohibited.

## 2. Terraform Schema Discovery

Before implementing the policy, I created a dedicated Terraform schema lab using AWS provider version `6.73.0`.

This was necessary because Terraform resource types do not expose security group rules using identical attribute structures.

I inspected the provider schema and actual Terraform plan JSON to identify the correct attributes.

### 2.1 Resource representations

| Resource | Protocol | Ports | IPv4 source | IPv6 source |
|---|---|---|---|---|
| `aws_security_group` | `ingress[].protocol` | `ingress[].from_port`, `to_port` | `ingress[].cidr_blocks` | `ingress[].ipv6_cidr_blocks` |
| `aws_vpc_security_group_ingress_rule` | `ip_protocol` | `from_port`, `to_port` | `cidr_ipv4` | `cidr_ipv6` |
| `aws_security_group_rule` | `protocol` | `from_port`, `to_port` | `cidr_blocks` | `ipv6_cidr_blocks` |

### 2.2 Important schema findings

- Inline security group rules are nested inside the `ingress` collection.
- Modern standalone rules represent one ingress rule per resource.
- Legacy standalone rules use a `type` attribute to distinguish ingress from egress.
- Computed attributes such as IDs and ARNs can be unknown during planning.
- Security relevant attributes must be evaluated using their actual plan JSON representation.

**Decision:** Implement separate evaluation logic for each resource type rather than assuming a shared schema.

## 3. SSH Detection Logic

The policy identifies SSH exposure using protocol and port information.

Supported protocol representations:

- `tcp`
- `6` - numeric TCP protocol identifier.
- `-1` - all protocols, which includes SSH.

For TCP rules, port 22 is considered exposed when the configured port range includes 22:

`from_port <= 22` and `to_port >= 22`

This also detects ranges such as TCP `20–25`, not just rules explicitly configured for port 22.

**Decision:** Treat all-protocol rules as SSH exposure regardless of port values because they permit all protocols.

## 4. Change Evaluation

Terraform plan JSON includes resource actions.

The policy evaluates resources with:

- `create`
- `update`

Delete-only changes are excluded because they remove existing configuration rather than introduce or retain the planned ingress exposure.

**Decision:** Evaluate active resource changes and exclude delete-only changes.

## 5. IPv4 and IPv6 Enforcement

Both unrestricted source ranges are independently prohibited:

| Address | Meaning | Result |
|---|---|---|
| `0.0.0.0/0` | All IPv4 addresses | Deny |
| `::/0` | All IPv6 addresses | Deny |

Restricted CIDRs are allowed by this policy.

**Decision:** IPv4 and IPv6 must both be evaluated. Checking IPv4 alone would leave an IPv6 exposure path undetected.

## 6. Unknown-Value Handling

Terraform cannot always determine every attribute during planning.

These values are represented in the plan JSON through `change.after_unknown`.

Ignoring unknown security-relevant values could allow potentially unrestricted SSH rules to pass policy evaluation.

I therefore implemented conservative unknown-value handling.

### 6.1 Unknown-value behavior by resource

| Resource | Unknown-value representation |
|---|---|
| Inline security group | Nested objects in `after_unknown.ingress`, aligned by rule index |
| Modern standalone rule | Boolean flags for individual attributes |
| Legacy standalone rule | Boolean flags for individual attributes and CIDR collection elements |

### 6.2 Security-relevant unknown attributes

The policy checks:

- Protocol
- Starting port
- Ending port
- IPv4 source CIDR
- IPv6 source CIDR

If a relevant attribute is unknown, the policy determines whether the unresolved configuration could represent public SSH exposure.

For example:

- Unknown protocol with a public source could represent TCP or all protocols.
- Unknown port with a public source could include port 22.
- Unknown CIDR with known TCP port 22 could represent an unrestricted source.

When the combination could represent unrestricted SSH exposure, the policy generates a violation.

### 6.3 Avoiding unrelated false positives

Unknown attributes that do not affect SSH exposure must not trigger this policy.

For example:

- Unknown security group ID.
- Unknown ingress description.
- Unknown unrelated metadata.

**Decision:** Only unknown security-relevant attributes contribute to conservative denial.

### 6.4 Inline rule alignment

Inline security group rules require special handling.

The `after_unknown.ingress` collection corresponds to `after.ingress` by index.

The implementation matches each planned ingress rule with its corresponding unknown-value metadata.

This prevents unknown attributes belonging to one rule from being incorrectly associated with another.

## 7. Violation Contract

Every policy violation must follow the project's canonical seven-field contract:

| Field | Purpose |
|---|---|
| `policy_id` | Unique policy identifier |
| `title` | Human-readable policy title |
| `severity` | Risk classification |
| `category` | Policy category |
| `resource` | Terraform resource address |
| `message` | Explanation of the violation |
| `remediation` | Recommended corrective action |

For AWS-NET-001:

- Policy ID: `AWS-NET-001`
- Severity: `HIGH`
- Category: `NETWORK`

Unknown-value violations use the same seven-field structure.

**Decision:** Policy identifiers and violation fields must remain consistent across all policies.

## 8. Conftest Integration

Conftest expects a string-valued `msg` field in its `deny` results.

Adding `msg` directly to the canonical violation object would alter the seven-field contract.

I therefore separated the policy output from the Conftest adapter.

- `violations` produces the canonical seven-field violation objects.
- `deny` uses `object.union()` to add `msg` for Conftest.

This allows Conftest to display actionable failure messages without changing the canonical violation structure.

**Decision:** Keep the canonical policy contract separate from tool-specific output requirements.

## 9. Testing Strategy

Testing was performed at two levels.

### 9.1 Unit testing

File:

`policies/network/tests/aws_net_001_test.rego`

The test suite covers:

- Public IPv4 SSH detection.
- Public IPv6 SSH detection.
- All three supported Terraform resource types.
- Restricted CIDR acceptance.
- Non-SSH port acceptance.
- TCP ranges containing port 22.
- All-protocol rules.
- Numeric TCP protocol.
- Egress exclusion.
- Delete-only exclusion.
- Seven-field violation contract.
- Unknown protocol, ports, and CIDRs.
- Unrelated unknown attributes.

**Final result:**

`27 tests, 27 passed, 0 warnings, 0 failures, 0 exceptions, 0 skipped`

### 9.2 Positive integration testing

I used the actual Terraform plan generated from:

`examples/phase-2-schema-lab/`

The initial configuration intentionally contained six unrestricted SSH exposures:

- Inline: IPv4 and IPv6.
- Modern standalone: IPv4 and IPv6.
- Legacy standalone: IPv4 and IPv6.

Conftest result:

`6 tests, 0 passed, 0 warnings, 6 failures, 0 exceptions`

These six failures were expected policy denials.

**Result:** All six unrestricted SSH exposures were detected.

### 9.3 Negative integration testing

I changed all six source CIDRs to restricted documentation-range addresses:

- IPv4: `203.0.113.10/32`
- IPv6: `2001:db8::10/128`

The SSH protocol and port configurations remained unchanged.

Conftest result:

`1 test, 1 passed, 0 warnings, 0 failures, 0 exceptions`

Conftest evaluates the entire Terraform plan as one input document. Therefore, one passing test represents successful evaluation of the complete compliant plan, not just one security group rule.

**Result:** No policy violations were detected.

## 10. Enforcement Decisions

The following enforcement decisions apply:

1. All violations block CI, regardless of severity.
2. Severity communicates risk; it does not determine whether a violation blocks deployment.
3. Unknown security-relevant values are handled conservatively.
4. Restricted CIDRs are accepted by this policy.
5. Egress rules are outside this policy's scope.
6. Delete-only changes are excluded.
7. Policy output must remain deterministic and follow the canonical violation contract.

## 11. Scope and Limitations

AWS-NET-001 specifically addresses unrestricted SSH ingress through the three supported Terraform security group resource types.

It does not evaluate:

- Other exposed ports.
- Other network access mechanisms.
- SSH exposure through resources outside its supported resource types.
- Whether a restricted CIDR is operationally approved or belongs to a trusted organization network.

Those concerns require separate controls or policies.

## 12. Final Validation and Completion

| Validation | Result |
|---|---|
| OPA syntax validation | Passed |
| Unit tests | 27/27 passed |
| Positive integration test | 6 violations detected |
| Negative integration test | 1 plan passed, 0 violations |
| Canonical violation contract | Verified |

**Final status: Implemented and validated.**

AWS-NET-001 establishes the implementation pattern for subsequent network policies:

1. Discover and validate Terraform resource schemas.
2. Inspect actual Terraform plan JSON.
3. Implement known-value detection.
4. Implement unknown-value handling.
5. Preserve the canonical violation contract.
6. Add positive and negative unit tests.
7. Validate against positive and negative Terraform plan fixtures.
8. Document implementation decisions.

---

**Next policy:** `AWS-NET-002` — Block unrestricted RDP ingress (TCP port 3389).