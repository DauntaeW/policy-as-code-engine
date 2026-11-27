# AWS-NET-003 — Block Unrestricted Public Database Ingress

## 1. Policy Metadata

| Field | Value |
|---|---|
| Policy ID | AWS-NET-003 |
| Title | Block unrestricted public database ingress |
| Severity | HIGH |
| Category | NETWORK |
| Status | Implemented |
| Policy Version | 1.0 |

## 2. Security Objective

Prevent AWS security groups from exposing common database services directly to unrestricted IPv4 or IPv6 sources.

The policy protects:

| Database | Protocol | Port |
|---|---|---:|
| Microsoft SQL Server | TCP | 1433 |
| MySQL | TCP | 3306 |
| PostgreSQL | TCP | 5432 |

A rule violates this policy when its protocol and port range permit access to a protected database port and its source includes an unrestricted public CIDR.

## 3. Terraform Resource Coverage

The policy evaluates these AWS provider resource representations:

- `aws_security_group` — inline ingress rules.
- `aws_security_group_rule` — legacy standalone ingress rules.
- `aws_vpc_security_group_ingress_rule` — modern standalone ingress rules.

Both IPv4 and IPv6 sources are evaluated.

The policy recognizes:

- `0.0.0.0/0` as unrestricted IPv4.
- `::/0` as unrestricted IPv6.

For inline security groups, unknown-value metadata is correlated with ingress rules by array index.

## 4. Evaluation Behavior

The policy evaluates proposed Terraform changes involving resource creation or updates.

Replacement operations are evaluated because they include a create action.

Delete-only and no-op changes are ignored.

Only ingress rules are evaluated for the legacy security-group rule resource.

The policy evaluates whether a rule's port range includes any protected database port.

A range spanning multiple protected database ports can produce multiple violations.

A single rule exposing both unrestricted IPv4 and IPv6 sources produces one violation per affected database port.

## 5. Unknown-Value Handling

The policy distinguishes confirmed exposure from indeterminate exposure.

Confirmed public exposure produces a violation.

If relevant protocol, port, or source information is unknown and the rule could expose a protected database port, the policy fails closed with an indeterminate violation.

Known restricted sources and known non-TCP protocols do not trigger violations.

Confirmed exposure takes precedence over indeterminate metadata to avoid duplicate reporting.

Unknown unrelated resource attributes do not independently trigger violations.

## 6. Violation Contract

Every violation follows the canonical seven-field contract:

- `policy_id`
- `title`
- `severity`
- `category`
- `resource`
- `message`
- `remediation`

The policy uses the shared Conftest adapter to expose the required `msg` field without changing the canonical violation structure.

## 7. Testing Strategy

### Unit Testing

The policy includes tests covering:

- Inline, legacy, and modern resource representations.
- PostgreSQL, MySQL, and SQL Server ports.
- IPv4 and IPv6 unrestricted sources.
- Wide port ranges.
- All-protocol rules.
- Non-TCP protocols.
- Restricted CIDRs.
- Ingress and egress behavior.
- Create, update, replacement, delete-only, and no-op actions.
- Unknown protocol, port, and CIDR values.
- Unknown unrelated attributes.
- Confirmed-exposure precedence.
- Violation contract and Conftest adapter.

**Results:**
- OPA tests: 73/73 passed.
- Conftest verification: 73/73 passed.
- No warnings, failures, exceptions, or skipped tests.

### Positive Integration Test

The Terraform schema lab generated a real Terraform plan containing unrestricted database ingress.

The fixture included:

- Three inline database rules.
- Six modern standalone rules.
- Six legacy standalone rules.
- IPv4 and IPv6 unrestricted sources.

**Expected result:** 15 policy violations.

**Observed result:** 15 policy violations.

GitHub Actions run: `45924004928`

The CI job correctly failed because the policy detected the intentionally introduced violations.

### Negative Integration Test

The Terraform fixture was updated to use restricted documentation-range CIDRs:

- IPv4: `203.0.113.10/32`
- IPv6: `2001:db8::10/128`

All 15 database rule definitions remained present.

**Expected result:** no policy violations.

**Observed result:** 3 Conftest integration checks passed, with zero failures.

GitHub Actions run: `45926341641`

## 8. Design Decisions

1. Support inline, legacy, and modern security-group ingress representations to avoid gaps caused by different Terraform resource models.
2. Evaluate port ranges rather than checking only exact port equality.
3. Treat unrestricted IPv4 and IPv6 sources equally.
4. Fail closed when relevant unknown values could conceal a public database exposure.
5. Ignore deletion-only operations because they do not introduce new exposure.
6. Emit one violation per affected database port and rule, rather than duplicating violations for IPv4 and IPv6 exposure on the same rule.
7. Keep policy violations aligned with the shared seven-field contract.

## 9. Limitations

This policy focuses on direct security-group ingress exposure for three common database services.

It does not independently evaluate:

- Network ACL behavior.
- Routing-table reachability.
- Application-layer authentication.
- Database-specific authorization.
- Other database ports not included in the protected-port catalog.
- Exposure through indirect network paths.

A restricted CIDR does not automatically establish that a resource is secure. It only means this specific unrestricted-public-ingress policy was not violated.

## 10. Final Acceptance

AWS-NET-003 is accepted after successful unit, positive integration, and negative integration testing.

The policy detects unrestricted public database ingress across the supported Terraform resource representations and permits the tested restricted-source configurations.

**Final status: IMPLEMENTED — VERSION 1.0**