# Policy Development Standard

**Document Type:** Engineering Standard  
**Project:** AWS Policy-as-Code Engine  
**Version:** 1.0  
**Status:** Active  
**Applies To:** Network, Encryption, and Governance Policies

---

## 1. Purpose

This document establishes a repeatable engineering process for designing, implementing, testing, and documenting policies within the AWS Policy-as-Code Engine.

The objective is to ensure every policy:

- Evaluates Terraform plan data accurately.
- Handles different AWS provider resource representations.
- Accounts for unknown values and resource lifecycle changes.
- Produces consistent, machine-readable violations.
- Is tested independently and through Terraform integration.
- Runs through GitHub Actions without requiring local Terraform execution or live AWS infrastructure.
- Has documented implementation decisions and validation evidence.

Every policy must follow the 11-step workflow defined below.

## 2. Standard 11-Step Development Workflow

### Step 1 — Discover Provider Schema

Identify the AWS provider version and inspect the schema for relevant resource types and attributes.

**Activities:**
- Identify applicable Terraform resource types.
- Inspect attribute names, types, and nesting.
- Identify required, optional, computed, and nested attributes.
- Confirm whether multiple resource representations exist.

**Acceptance criteria:**
- Relevant resource types are identified.
- Relevant attributes and their expected types are understood.
- Provider version is recorded.

### Step 2 — Inspect Resource Representation

Inspect actual Terraform plan JSON rather than relying exclusively on provider documentation.

**Activities:**
- Generate a Terraform plan through GitHub Actions.
- Inspect relevant entries in `resource_changes`.
- Examine `change.actions`, `change.after`, and `change.after_unknown`.
- Compare inline, modern, and legacy resource representations where applicable.

**Acceptance criteria:**
- Actual plan JSON confirms the expected resource structure.
- Attribute paths are verified.
- Relevant differences between resource representations are documented.

### Step 3 — Identify Relevant Attributes

Build an attribute matrix describing which fields determine policy compliance.

**Activities:**
- Identify attributes that determine whether a resource violates the policy.
- Identify alternative representations of equivalent configuration.
- Define matching conditions and boundary cases.
- Identify attributes that are irrelevant to the security decision.

**Acceptance criteria:**
- Each detection condition maps to verified Terraform attributes.
- Equivalent resource representations are accounted for.
- Boundary conditions are explicitly defined.

### Step 4 — Evaluate Create, Update, and Delete Behavior

Determine how the policy evaluates Terraform resource lifecycle actions.

**Standard approach:**
- `["create"]`: Evaluate the planned resource.
- `["update"]`: Evaluate the planned resource.
- `["delete", "create"]`: Evaluate the replacement configuration.
- `["create", "delete"]`: Evaluate the replacement configuration.
- `["delete"]`: Ignore because there is no remaining planned resource configuration.
- `["no-op"]`: Ignore unless the policy explicitly requires otherwise.

Evaluate the planned `change.after` configuration rather than relying on the previous state in `change.before`.

**Acceptance criteria:**
- Create and update behavior is defined.
- Both replacement action orderings are considered.
- Delete-only behavior is defined.
- Tests cover relevant lifecycle actions.

### Step 5 — Handle Unknown Values

Terraform plans can contain attributes whose final values are not known until apply.

Inspect `change.after_unknown` and determine whether an unknown attribute can change the policy decision.

**Standard approach:**
- Fail closed when an unknown security-relevant value prevents a reliable compliance decision.
- Do not automatically fail when an unknown attribute cannot affect the policy decision.
- Distinguish confirmed violations from indeterminate violations.
- Never describe an indeterminate condition as a confirmed exposure.
- Ensure confirmed violations take precedence over indeterminate findings when both are present.

**Acceptance criteria:**
- Relevant unknown attributes are identified.
- Indeterminate conditions are handled explicitly.
- Irrelevant unknown attributes do not create unnecessary violations.
- Unit tests cover the important unknown-value scenarios.

### Step 6 — Define the Violation Contract

Every policy must use the same seven canonical violation fields:

| Field | Purpose |
|---|---|
| `policy_id` | Unique policy identifier |
| `title` | Human-readable policy title |
| `severity` | CRITICAL, HIGH, MEDIUM, or LOW |
| `category` | NETWORK, ENCRYPTION, or GOVERNANCE |
| `resource` | Terraform resource address |
| `message` | Explanation of the violation |
| `remediation` | Recommended corrective action |

**Rules:**
- Policy identifiers follow `AWS-{CATEGORY}-{NUMBER}`.
- Numbers use three-digit zero-padded identifiers.
- Severity must use uppercase values.
- Every violation must contain all seven fields.
- All violations block CI initially, regardless of severity.

**Conftest compatibility:**

Conftest expects a `msg` field for readable denial output. Add it through the adapter without modifying the canonical violation object:

```rego
deny contains result if {
    some violation in violations
    result := object.union(
        violation,
        {"msg": violation.message}
    )
}
```

Unit tests should primarily validate `violations`, not the adapter.

**Acceptance criteria:**
- Policy metadata is defined.
- Every violation contains exactly the seven canonical fields.
- The Conftest adapter produces readable denial messages.

### Step 7 — Integrate with Conftest

Implement the policy in the appropriate Rego file and confirm it integrates with the existing policy engine.

**Activities:**
- Place the policy in its appropriate category directory.
- Use the existing package architecture.
- Implement the canonical `violations` rule.
- Implement the Conftest `deny` adapter.
- Run Rego compilation and Conftest verification.

**Repository conventions:**

```text
policies/
├── network/
│   ├── aws_net_001.rego
│   ├── aws_net_002.rego
│   ├── aws_net_003.rego
│   └── tests/
│       ├── aws_net_001_test.rego
│       ├── aws_net_002_test.rego
│       └── aws_net_003_test.rego
├── encryption/
└── governance/
```

**Important: Shared Rego package behavior**

The existing network policies use:

```rego
package main
```

Policies sharing this package contribute to the same namespace. Their `violations` rules aggregate.

Therefore:

- Do not assume `data.main.violations` contains findings from only one policy.
- Filter policy-specific results by `policy_id` in unit tests.
- Use unique helper names across policy test files.
- Use unique test rule names across files sharing the package.
- Do not change the existing package architecture merely to isolate a test.

This convention prevents false test failures caused by findings from other policies.

**Acceptance criteria:**
- Policy compiles.
- Conftest discovers the policy.
- Existing policies continue to work.
- No namespace or rule-name collisions are introduced.

### Step 8 — Unit Testing

Write isolated OPA tests for policy behavior.

**Location:**

```text
policies/{category}/tests/{policy_file}_test.rego
```

Tests should cover applicable scenarios, including:

- Confirmed violations.
- Compliant configurations.
- IPv4 and IPv6 where applicable.
- Alternative resource representations.
- Boundary conditions.
- Multiple relevant rules within one resource.
- Create, update, delete, and replacement actions.
- Unknown-value handling.
- Violation contract.
- Conftest adapter behavior.

When testing a policy in the shared `main` package, filter findings by `policy_id` before asserting counts or fields.

**Acceptance criteria:**
- All policy-specific unit tests pass.
- Existing policy tests continue to pass.
- No unexpected findings are introduced.
- The seven-field contract is verified.

### Step 9 — Positive Integration Test

Prove that the policy detects deliberately non-compliant Terraform configuration.

**Procedure:**

1. Introduce controlled violations into the Terraform schema-lab fixture.
2. Generate a Terraform plan on GitHub-hosted infrastructure.
3. Run Conftest against the plan.
4. Capture the expected policy denials.
5. Assert the expected `policy_id`.
6. Assert the expected violation count.
7. Confirm the workflow fails if an expected violation is missing.

**Expected-denial handling:**

The policy should deny the non-compliant configuration. The integration workflow should recognize those denials as the expected test result.

Do not weaken the production policy to make the integration test pass.

The workflow should finish successfully only when the expected violations have been detected and verified.

**Acceptance criteria:**
- Terraform plan generation succeeds.
- Every deliberately introduced violation is detected.
- The correct policy ID is returned.
- The expected violation count is verified.
- GitHub Actions reports a successful integration test.

### Step 10 — Negative Integration Test

Prove that compliant Terraform configuration passes policy enforcement.

**Procedure:**

1. Correct the deliberately non-compliant configuration.
2. Replace violating values with compliant values.
3. Generate a fresh Terraform plan.
4. Run normal Conftest enforcement.
5. Confirm the policy does not report violations.
6. Confirm the workflow succeeds.

**Important:**

Restore normal Conftest enforcement. Do not suppress denials, bypass policy checks, or create exceptions simply to obtain a passing workflow.

**Acceptance criteria:**
- Terraform plan generation succeeds.
- The configuration satisfies the policy.
- Normal Conftest enforcement passes.
- GitHub Actions reports a successful integration test.

### Step 11 — Decision Documentation

Create a policy-specific decision record.

**Location:**

```text
docs/decisions/AWS-{POLICY-ID}.md
```

Each record should document:

1. Policy Objective
2. Terraform Schema Discovery
3. Detection Logic
4. Change Evaluation
5. IPv4/IPv6 Enforcement, where applicable
6. Unknown-Value Handling
7. Violation Contract
8. Conftest Integration
9. Testing Strategy
10. Enforcement Decisions
11. Scope and Limitations
12. Final Validation and Completion

Include actual test results and GitHub Actions run IDs where available.

Document why implementation decisions were made, not simply what code was written.

**Acceptance criteria:**
- Decision record exists.
- All relevant implementation decisions are documented.
- Unit and integration test evidence is recorded.
- Final validation is confirmed.
- Changes are committed and pushed.

---

## 3. GitHub Actions Execution Standard

Terraform and Conftest integration testing must run on GitHub-hosted runners.

**Execution requirements:**
- Use the existing Terraform evidence workflow.
- Pin Terraform, Conftest, and provider versions.
- Generate Terraform plans without deploying infrastructure.
- Use mock or placeholder AWS credentials where the provider requires them.
- Do not execute `terraform apply`.
- Do not create billable AWS resources for policy validation.
- Preserve normal Conftest enforcement outside deliberate positive-test assertions.

The local development environment is used for editing, reviewing diffs, Git operations, and optional lightweight validation. GitHub Actions is the authoritative environment for Terraform integration testing.

## 4. Failure Investigation Standard

When a test or workflow fails, investigate the failure before modifying policy logic.

**Investigation order:**

1. Identify the exact failing test or workflow step.
2. Determine whether the failure is in Terraform, Rego, Conftest, or the test assertion.
3. Inspect the relevant Terraform plan JSON.
4. Check whether another policy contributed findings to the shared package.
5. Check helper and test rule names for collisions.
6. Verify the expected policy ID and violation count.
7. Correct the underlying issue.
8. Rerun the affected unit or integration tests.
9. Confirm previously passing policies still pass.

Do not rewrite working policy logic to compensate for incorrect test assumptions.

## 5. Repository Structure

The following structure is the intended organization:

```text
.
├── .github/
│   └── workflows/
│       └── terraform-evidence.yml
├── docs/
│   ├── decisions/
│   │   ├── AWS-NET-001.md
│   │   ├── AWS-NET-002.md
│   │   └── ...
│   └── POLICY-DEVELOPMENT-STANDARD.md
├── examples/
│   └── phase-2-schema-lab/
│       └── main.tf
└── policies/
    ├── network/
    │   ├── aws_net_001.rego
    │   ├── aws_net_002.rego
    │   ├── aws_net_003.rego
    │   └── tests/
    ├── encryption/
    └── governance/
```

New policies should follow the established structure. Additional fixtures or workflows should only be introduced when a genuine technical requirement justifies them.

## 6. Versioning and Policy Evolution

The violation contract begins at version 1.0.

- Backward-compatible additions should increment the minor version.
- Breaking changes to the contract should increment the major version.
- Existing policy identifiers must remain stable.
- Changes to detection logic must be covered by updated unit and integration tests.
- Changes to enforcement behavior must be documented.

## 7. Definition of Done

A policy is not considered complete until all of the following are satisfied:

- [ ] All 11 development steps completed.
- [ ] Provider schema and actual Terraform plan representation inspected.
- [ ] Resource attributes and lifecycle behavior documented.
- [ ] Unknown-value handling implemented and tested.
- [ ] Seven-field violation contract verified.
- [ ] Conftest integration successful.
- [ ] Policy-specific unit tests pass.
- [ ] Existing policy tests continue to pass.
- [ ] Positive integration test detects all expected violations.
- [ ] Negative integration test accepts compliant configuration.
- [ ] GitHub Actions validation succeeds.
- [ ] Policy decision record completed.
- [ ] Changes committed and pushed.

---

## 8. Engineering Principles

The following principles govern development across the entire policy engine:

1. **Evidence over assumptions:** Use actual Terraform plan data to validate resource representations.
2. **Fail closed where justified:** Unknown security-relevant values must not silently bypass enforcement.
3. **Consistent contracts:** All policies produce the same canonical violation structure.
4. **Test isolation:** Shared Rego namespaces must not cause cross-policy test contamination.
5. **Realistic integration testing:** Positive and negative tests must exercise actual Terraform plans.
6. **No unnecessary infrastructure:** Policy validation must not require live AWS deployments.
7. **Preserve working functionality:** New policies must not regress existing policies.
8. **Document decisions:** Implementation rationale and test evidence must be retained.
9. **Repeatability:** Every policy follows the same 11-step development workflow.

**Final principle:** A policy is only as reliable as the evidence proving that it detects non-compliant configurations and accepts compliant ones.