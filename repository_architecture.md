policy-as-code-engine/
│
├── .github/
│   └── workflows/
│       └── policy-ci.yml
│
├── policies/
│   ├── network/
│   │   ├── security_groups.rego
│   │   ├── s3_public_access.rego
│   │   └── network_test.rego
│   │
│   ├── encryption/
│   │   ├── ebs_encryption.rego
│   │   ├── s3_encryption.rego
│   │   ├── rds_encryption.rego
│   │   ├── kms_requirements.rego
│   │   └── encryption_test.rego
│   │
│   └── governance/
│       ├── mandatory_tags.rego
│       ├── naming_conventions.rego
│       ├── environment_rules.rego
│       └── governance_test.rego
│
├── fixtures/
│   ├── passing/
│   └── failing/
│
├── examples/
│   └── terraform-consumer/
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
│
├── scripts/
│   └── evaluate.sh
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── POLICY_CATALOG.md
│   ├── CONTRIBUTING.md
│   ├── POLICY_VERSIONING.md
│   └── THREAT_MODEL.md
│
├── .gitignore
├── .conftest.yaml
├── README.md
└── LICENSE