# Policy-as-Code Engine — Project Scope & Implementation Plan

**Project:** Policy-as-Code Engine  
**Version:** 1.0  
**Status:** Planning  
**Primary objective:** Build a reusable, version-controlled infrastructure policy enforcement engine using OPA, Rego, Conftest, Terraform, and GitHub Actions.

---

## 1. Project Objectives

Build an independent policy enforcement platform that evaluates Terraform infrastructure plans against custom organizational security, encryption, and governance requirements.

The platform must:

- Evaluate Terraform plan JSON before infrastructure deployment.
- Enforce custom organizational policies using Rego.
- Return actionable violations identifying the offending resource and policy.
- Automatically reject noncompliant pull requests.
- Support automated testing of policies.
- Support independent policy versioning and reuse across Terraform repositories.
- Operate without requiring an active AWS account.

## 2. Project Constraints

| Constraint | Implementation |
|---|---|
| Single AWS account | No AWS deployment required |
| Limited laptop RAM | No LocalStack or container-heavy environment |
| Development environment | VS Code |
| Source control | GitHub |
| Infrastructure testing | Terraform plan and JSON fixtures |
| Policy evaluation | OPA and Conftest |
| Automation | GitHub Actions |
| Budget | Zero AWS infrastructure expenditure |

The initial implementation must run locally and in GitHub Actions without provisioning AWS resources.

## 3. Architecture

Two independent repositories:

**Repository A: `policy-as-code-engine`**

Contains:
- Rego policy definitions.
- Policy unit tests.
- Passing and failing test fixtures.
- CI workflows.
- Policy documentation.
- Versioning and release management.

**Repository B: `policy-engine-consumer`**

Contains:
- Sample Terraform infrastructure.
- Terraform configuration and variables.
- Terraform plan generation.
- Integration with the policy engine.
- GitHub Actions consumer workflow.

### Evaluation flow

1. Developer submits a Terraform change through a pull request.
2. GitHub Actions initializes Terraform.
3. Terraform generates an execution plan.
4. Terraform converts the plan into JSON.
5. Conftest loads the specified policy version.
6. Rego evaluates the Terraform plan.
7. The evaluation returns violations or a successful result.
8. GitHub Actions publishes the evaluation result.
9. Noncompliant changes fail the required CI check.

No infrastructure is applied as part of this project's initial implementation.

## 4. Policy Requirements

Minimum target: 10 custom policies across three categories.

### Category A — Network Security

| ID | Policy | Expected behavior |
|---|---|---|
| NET-001 | SSH restriction | Reject unrestricted inbound TCP port 22 |
| NET-002 | RDP restriction | Reject unrestricted inbound TCP port 3389 |
| NET-003 | S3 public access | Reject configurations that violate the organization's S3 public-access requirements |

### Category B — Encryption

| ID | Policy | Expected behavior |
|---|---|---|
| ENC-001 | EBS encryption | Require EBS volume encryption |
| ENC-002 | S3 encryption | Require default server-side encryption |
| ENC-003 | RDS encryption | Require storage encryption |
| ENC-004 | Customer-managed KMS | Require an approved customer-managed KMS key for designated sensitive resources |

### Category C — Governance

| ID | Policy | Expected behavior |
|---|---|---|
| GOV-001 | Mandatory tags | Require Environment, Owner, and Project |
| GOV-002 | Naming conventions | Enforce organizational naming standards |
| GOV-003 | Environment validation | Only permit approved environment values |

Every policy must have:

- A unique policy identifier.
- A clear description.
- A business/security justification.
- A severity level.
- A remediation recommendation.
- At least one failing test.
- At least one passing test.

Policies must evaluate the planned resource configuration, not simply the Terraform source code.

Where a value is unknown at plan time, policies must handle that condition deliberately rather than incorrectly assuming the resource is compliant.

## 5. Policy Testing Requirements

We will implement two testing layers.

**Layer 1: Rego unit testing**

Use `opa test` to test the policy logic directly.

Requirements:
- Positive test cases.
- Negative test cases.
- Edge cases.
- Unknown or null value handling where applicable.

**Layer 2: Conftest integration testing**

Use `conftest test` to evaluate Terraform plan JSON fixtures.

Requirements:
- Valid infrastructure passes.
- Invalid infrastructure fails.
- Multiple violations are reported.
- Resource addresses are included in violation messages.
- Tests produce predictable results.

Passing and failing fixtures must be maintained independently.

## 6. Terraform Integration

The consumer repository will generate Terraform plan JSON.

Expected workflow:

1. `terraform init`
2. `terraform plan -out=plan.tfplan`
3. `terraform show -json plan.tfplan > plan.json`
4. `conftest test plan.json --policy <policy-directory>`

The integration must support a local Terraform backend and test infrastructure that doesn't require live AWS resources.

We will initially use deterministic Terraform plan fixtures for policy testing, then introduce actual Terraform-generated plan JSON for integration testing.

Avoid AWS data sources and operations that require live API calls.

## 7. CI/CD Requirements

### Policy engine CI

Triggered by:
- Pull requests.
- Changes to policy files.
- Changes to policy tests.
- Changes to CI configuration.

Pipeline:

1. Check out repository.
2. Install pinned OPA and Conftest versions.
3. Validate policy syntax.
4. Execute Rego unit tests.
5. Evaluate passing fixtures.
6. Evaluate failing fixtures.
7. Confirm expected pass/fail results.
8. Fail the pipeline if a test behaves unexpectedly.

### Consumer CI

Triggered by Terraform pull requests.

Pipeline:

1. Check out consumer repository.
2. Install Terraform.
3. Initialize Terraform.
4. Generate plan JSON.
5. Retrieve the pinned policy engine version.
6. Run Conftest.
7. Generate a readable policy evaluation summary.
8. Publish results to the pull request.
9. Fail the required check if violations exist.

GitHub Actions must use least-privilege permissions.

Terraform plan JSON must not be unnecessarily uploaded as a public artifact or exposed in CI logs because plans can contain sensitive information.

## 8. Policy Versioning and Reusability

The policy engine must be consumable independently of its own repository.

Requirements:

- Git tags for policy releases.
- Semantic versioning.
- Versioned release notes.
- Consumer repository pins an exact policy release or immutable commit SHA.
- Consumer must not silently consume unreviewed policy changes.
- Policy upgrades must be deliberate and tested.

Demonstrate consumption of the policy engine from a separate Terraform repository.

## 9. Policy Evolution Demonstration

Create a documented scenario:

1. A Terraform configuration passes the current policy checks.
2. A new organizational requirement is introduced.
3. A new Rego policy is implemented.
4. The same Terraform configuration now fails.
5. The violation is reported with a remediation recommendation.
6. The consumer updates to the new policy version.

This demonstrates that the policy engine can evolve as organizational requirements change.

## 10. Documentation Deliverables

| Document | Purpose |
|---|---|
| README.md | Project overview, installation, usage and quick start |
| ARCHITECTURE.md | Architecture, components and evaluation flow |
| POLICY_CATALOG.md | Complete policy inventory and explanations |
| CONTRIBUTING.md | Instructions for adding and testing policies |
| POLICY_VERSIONING.md | Release and dependency management |
| THREAT_MODEL.md | Security risks, assumptions and mitigations |

Additional evidence:

- Architecture diagram.
- Passing policy evaluation logs.
- Failing policy evaluation logs.
- Rego unit test results.
- GitHub Actions execution screenshots or logs.
- Blocked pull request demonstration.
- Policy evolution demonstration.

## 11. Implementation Phases

### Phase 0 — Project Preparation
- [ ] Confirm project scope.
- [ ] Confirm architecture.
- [ ] Prepare VS Code.
- [ ] Verify Git installation.
- [ ] Verify Terraform installation.
- [ ] Verify OPA installation.
- [ ] Verify Conftest installation.
- [ ] Create GitHub repositories.
- [ ] Establish repository structure.

### Phase 1 — Foundations
- [ ] Understand OPA, Rego and Conftest.
- [ ] Understand Terraform plan JSON.
- [ ] Understand how Conftest evaluates Terraform plans.
- [ ] Build the first simple policy.
- [ ] Run the first passing test.
- [ ] Run the first failing test.

### Phase 2 — Network Policies
- [ ] Implement NET-001.
- [ ] Implement NET-002.
- [ ] Implement NET-003.
- [ ] Write unit tests.
- [ ] Write integration fixtures.
- [ ] Validate all policies.

### Phase 3 — Encryption Policies
- [ ] Implement ENC-001.
- [ ] Implement ENC-002.
- [ ] Implement ENC-003.
- [ ] Implement ENC-004.
- [ ] Write unit tests.
- [ ] Write integration fixtures.
- [ ] Validate all policies.

### Phase 4 — Governance Policies
- [ ] Implement GOV-001.
- [ ] Implement GOV-002.
- [ ] Implement GOV-003.
- [ ] Write unit tests.
- [ ] Write integration fixtures.
- [ ] Validate all policies.

### Phase 5 — Policy Engine CI/CD
- [ ] Build GitHub Actions workflow.
- [ ] Pin tool versions.
- [ ] Automate policy validation.
- [ ] Automate unit testing.
- [ ] Automate fixture evaluation.
- [ ] Demonstrate pipeline failure.
- [ ] Demonstrate successful pipeline execution.

### Phase 6 — Terraform Consumer
- [ ] Create separate consumer repository.
- [ ] Build sample Terraform infrastructure.
- [ ] Generate Terraform plan JSON.
- [ ] Integrate Conftest.
- [ ] Consume pinned policy version.
- [ ] Demonstrate compliant infrastructure.
- [ ] Demonstrate noncompliant infrastructure.

### Phase 7 — Pull Request Enforcement
- [ ] Configure GitHub Actions permissions.
- [ ] Implement policy evaluation reporting.
- [ ] Publish violations as PR comments.
- [ ] Configure required status checks.
- [ ] Demonstrate blocked PR.
- [ ] Demonstrate successful PR.

### Phase 8 — Versioning and Policy Evolution
- [ ] Establish semantic versioning.
- [ ] Create first policy release.
- [ ] Pin release in consumer repository.
- [ ] Introduce a new policy requirement.
- [ ] Demonstrate policy version upgrade.
- [ ] Demonstrate previously passing infrastructure failing.

### Phase 9 — Finalization
- [ ] Complete documentation.
- [ ] Complete architecture diagram.
- [ ] Complete policy catalog.
- [ ] Review security considerations.
- [ ] Review repository structure.
- [ ] Validate all tests.
- [ ] Capture final evidence.
- [ ] Update GitHub repository descriptions.

## 12. Definition of Done

The project is complete when:

1. At least 10 custom organizational policies are implemented.
2. All policies have passing and failing tests.
3. Terraform plan JSON can be evaluated successfully.
4. Policy evaluation works locally.
5. Policy evaluation works in GitHub Actions.
6. Noncompliant Terraform changes fail CI.
7. Violations identify the offending resource and explain remediation.
8. A separate Terraform repository consumes the policy engine.
9. Policy versions are independently managed.
10. A policy evolution scenario is demonstrated.
11. All documentation and demonstration evidence are available in GitHub.

## 13. Explicitly Out of Scope

To keep the project focused:

- AWS multi-account architecture.
- Live AWS infrastructure deployment.
- LocalStack.
- Kubernetes admission controllers.
- Runtime workload security.
- Production policy distribution infrastructure.
- Enterprise OPA management platforms.
- Integration with the Cost Gate and IaC Vending Machine until those projects are developed.

These can become future extensions.

## 14. Engineering Quality Standards

Throughout implementation:

- Pin dependency versions.
- Use least-privilege GitHub Actions permissions.
- Avoid hardcoded credentials.
- Avoid exposing Terraform plan secrets.
- Keep policies modular.
- Use meaningful policy identifiers.
- Write tests before considering a policy complete.
- Document design decisions and trade-offs.
- Keep policy logic separate from Terraform infrastructure.
- Prefer deterministic, reproducible testing.

**Final outcome:** A reusable, tested, version-controlled infrastructure policy enforcement engine that can be integrated into different Terraform repositories as a security gate.