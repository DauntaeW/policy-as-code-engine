package main

# AWS-NET-004
# Prevent Public S3 Bucket Exposure
#
# Severity: CRITICAL
# Category: NETWORK
#
# Supports:
# - Normalized unit-test input: input.net004.resources
# - Terraform plan input: input.resource_changes
#
# Terraform plan configuration-reference correlation and
# complete nested-module handling are validated separately
# during integration testing.

net004_required_pab_controls := {
	"block_public_acls",
	"ignore_public_acls",
	"block_public_policy",
	"restrict_public_buckets",
}

net004_resources := input.net004.resources if {
	is_object(input.net004)
	is_array(input.net004.resources)
}

net004_resources := input.resource_changes if {
	not is_object(input.net004)
	is_array(input.resource_changes)
}

net004_actions(resource) := object.get(
	resource,
	"actions",
	object.get(object.get(resource, "change", {}), "actions", []),
)

net004_after(resource) := object.get(
	resource,
	"after",
	object.get(object.get(resource, "change", {}), "after", {}),
)

net004_before(resource) := object.get(
	resource,
	"before",
	object.get(object.get(resource, "change", {}), "before", {}),
)

net004_after_unknown(resource) := object.get(
	resource,
	"after_unknown",
	object.get(object.get(resource, "change", {}), "after_unknown", {}),
)

net004_address(resource) := object.get(resource, "address", "unknown")

net004_resource_type(resource) := object.get(resource, "type", "")

net004_is_active(resource) if {
	actions := net004_actions(resource)
	"create" in actions
}

net004_is_active(resource) if {
	actions := net004_actions(resource)
	"update" in actions
}

net004_is_delete_only(resource) if {
	actions := net004_actions(resource)
	"delete" in actions
	not "create" in actions
	not "update" in actions
}

net004_violation(resource, message, remediation) := {
	"policy_id": "AWS-NET-004",
	"title": "Prevent Public S3 Bucket Exposure",
	"severity": "CRITICAL",
	"category": "NETWORK",
	"resource": net004_address(resource),
	"message": message,
	"remediation": remediation,
}

# ---------------------------------------------------------
# ACL detection
# ---------------------------------------------------------

net004_public_canned_acl(resource) if {
	after := net004_after(resource)
	acl := object.get(after, "acl", "")

	acl in {
		"public-read",
		"public-read-write",
		"authenticated-read",
	}
}

net004_public_grant(resource) if {
	after := net004_after(resource)
	access_policy := object.get(after, "access_control_policy", [])

	some policy in access_policy
	grants := object.get(policy, "grant", [])

	some grant in grants
	grantees := object.get(grant, "grantee", [])

	some grantee in grantees
	uri := object.get(grantee, "uri", "")

	uri in {
		"http://acs.amazonaws.com/groups/global/AllUsers",
		"http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
	}
}

net004_public_legacy_grant(resource) if {
	after := net004_after(resource)
	grants := object.get(after, "grant", [])

	some grant in grants
	grantee := object.get(grant, "grantee", {})
	uri := object.get(grantee, "uri", "")

	uri in {
		"http://acs.amazonaws.com/groups/global/AllUsers",
		"http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
	}
}

net004_acl_unknown(resource) if {
	unknown := net004_after_unknown(resource)
	object.get(unknown, "access_control_policy", false) == true
}

net004_acl_unknown(resource) if {
	unknown := net004_after_unknown(resource)
	object.get(unknown, "acl", false) == true
}

net004_acl_unknown(resource) if {
	unknown := net004_after_unknown(resource)
	object.get(unknown, "grant", false) == true
}

net004_acl_violation(resource) if {
	net004_is_active(resource)
	net004_resource_type(resource) in {
		"aws_s3_bucket",
		"aws_s3_bucket_acl",
	}
	net004_public_canned_acl(resource)
}

net004_acl_violation(resource) if {
	net004_is_active(resource)
	net004_resource_type(resource) in {
		"aws_s3_bucket",
		"aws_s3_bucket_acl",
	}
	net004_public_grant(resource)
}

net004_acl_violation(resource) if {
	net004_is_active(resource)
	net004_resource_type(resource) == "aws_s3_bucket"
	net004_public_legacy_grant(resource)
}

net004_acl_indeterminate(resource) if {
	net004_is_active(resource)
	net004_resource_type(resource) in {
		"aws_s3_bucket",
		"aws_s3_bucket_acl",
	}
	net004_acl_unknown(resource)
}

# ---------------------------------------------------------
# Bucket policy detection
# ---------------------------------------------------------

net004_policy_is_public(policy) if {
	statements := policy.Statement
	is_array(statements)

	some statement in statements
	statement.Effect == "Allow"
	net004_wildcard_principal(statement.Principal)
}

net004_wildcard_principal(principal) if {
	principal == "*"
}

net004_wildcard_principal(principal) if {
	principal.AWS == "*"
}

net004_wildcard_principal(principal) if {
	some value in principal.AWS
	value == "*"
}

net004_policy_parsed(policy_string) := parsed if {
	parsed := json.unmarshal(policy_string)
}

net004_policy_violation(resource) if {
	net004_is_active(resource)
	net004_resource_type(resource) == "aws_s3_bucket_policy"

	after := net004_after(resource)
	policy_string := after.policy
	parsed := net004_policy_parsed(policy_string)

	net004_policy_is_public(parsed)
}

net004_policy_indeterminate(resource) if {
	net004_is_active(resource)
	net004_resource_type(resource) == "aws_s3_bucket_policy"

	unknown := net004_after_unknown(resource)
	object.get(unknown, "policy", false) == true
}

net004_policy_indeterminate(resource) if {
	net004_is_active(resource)
	net004_resource_type(resource) == "aws_s3_bucket_policy"

	after := net004_after(resource)
	policy_string := object.get(after, "policy", "")
	is_string(policy_string)
	policy_string != ""

	not net004_policy_parsed(policy_string)
}

# ---------------------------------------------------------
# Public Access Block detection
# ---------------------------------------------------------

net004_pab_incomplete(resource) if {
	after := net004_after(resource)
	unknown := net004_after_unknown(resource)

	some control in net004_required_pab_controls
	object.get(unknown, control, false) != true
	object.get(after, control, false) != true
}

net004_pab_unknown(resource) if {
	unknown := net004_after_unknown(resource)

	some control in net004_required_pab_controls
	object.get(unknown, control, false) == true
}

net004_pab_violation(resource) if {
	net004_is_active(resource)
	net004_resource_type(resource) in {
		"aws_s3_bucket_public_access_block",
		"aws_s3_account_public_access_block",
	}
	net004_pab_incomplete(resource)
}

net004_pab_indeterminate(resource) if {
	net004_is_active(resource)
	net004_resource_type(resource) in {
		"aws_s3_bucket_public_access_block",
		"aws_s3_account_public_access_block",
	}
	net004_pab_unknown(resource)
}

net004_pab_removal_violation(resource) if {
	net004_is_delete_only(resource)
	net004_resource_type(resource) in {
		"aws_s3_bucket_public_access_block",
		"aws_s3_account_public_access_block",
	}

	before := net004_before(resource)

	some control in net004_required_pab_controls
	object.get(before, control, false) == true
}

# ---------------------------------------------------------
# Canonical violations
# ---------------------------------------------------------

net004_violations contains violation if {
	some resource in net004_resources
	net004_acl_violation(resource)

	violation := net004_violation(
		resource,
		"S3 bucket ACL grants public access",
		"Remove public ACL grants and use private ACL settings. Enable all four S3 public access block controls.",
	)
}

net004_violations contains violation if {
	some resource in net004_resources
	net004_acl_indeterminate(resource)

	not net004_acl_violation(resource)

	violation := net004_violation(
		resource,
		"S3 ACL exposure could not be conclusively evaluated",
		"Provide known ACL and grant values so public access can be evaluated.",
	)
}

net004_violations contains violation if {
	some resource in net004_resources
	net004_policy_violation(resource)

	violation := net004_violation(
		resource,
		"S3 bucket policy permits public access",
		"Remove wildcard principals from Allow statements and restrict access to trusted principals.",
	)
}

net004_violations contains violation if {
	some resource in net004_resources
	net004_policy_indeterminate(resource)

	not net004_policy_violation(resource)

	violation := net004_violation(
		resource,
		"S3 bucket policy exposure could not be conclusively evaluated",
		"Provide a valid, known bucket policy so public access can be evaluated.",
	)
}

net004_violations contains violation if {
	some resource in net004_resources
	net004_pab_violation(resource)

	violation := net004_violation(
		resource,
		"S3 public access block configuration is insufficient",
		"Enable block_public_acls, ignore_public_acls, block_public_policy, and restrict_public_buckets.",
	)
}

net004_violations contains violation if {
	some resource in net004_resources
	net004_pab_indeterminate(resource)

	not net004_pab_violation(resource)

	violation := net004_violation(
		resource,
		"S3 public access block configuration could not be conclusively evaluated",
		"Provide known values for all four S3 public access block controls.",
	)
}

net004_violations contains violation if {
	some resource in net004_resources
	net004_pab_removal_violation(resource)

	violation := net004_violation(
		resource,
		"S3 public access block protection is being removed",
		"Retain effective account-level or bucket-level public access block protection.",
	)
}

# Integrate with the existing shared network violations set.
violations contains violation if {
	some violation in net004_violations
}
