package main

import rego.v1

# AWS-NET-004
# Step 8: Unit tests

net004_test_acl_input(resource) := {
	"net004": {
		"resources": [resource],
	},
}

net004_test_evaluate(resource) := result if {
	result := data.main.net004_violations
		with input as net004_test_acl_input(resource)
}

net004_test_pab_controls := {
	"block_public_acls": true,
	"ignore_public_acls": true,
	"block_public_policy": true,
	"restrict_public_buckets": true,
}

# ACL tests

test_net004_private_canned_acl_passes if {
	count(net004_test_evaluate({
		"address": "aws_s3_bucket_acl.example",
		"type": "aws_s3_bucket_acl",
		"actions": ["create"],
		"after": {"acl": "private"},
		"after_unknown": {},
	})) == 0
}

test_net004_public_read_acl_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_acl.example",
		"type": "aws_s3_bucket_acl",
		"actions": ["create"],
		"after": {"acl": "public-read"},
		"after_unknown": {},
	})

	contains(violation.message, "ACL grants public access")
}

test_net004_public_read_write_acl_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_acl.example",
		"type": "aws_s3_bucket_acl",
		"actions": ["create"],
		"after": {"acl": "public-read-write"},
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
}

test_net004_authenticated_read_acl_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_acl.example",
		"type": "aws_s3_bucket_acl",
		"actions": ["create"],
		"after": {"acl": "authenticated-read"},
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
}

test_net004_all_users_grant_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_acl.example",
		"type": "aws_s3_bucket_acl",
		"actions": ["create"],
		"after": {
			"access_control_policy": [{
				"grant": [{
					"grantee": [{
						"type": "Group",
						"uri": "http://acs.amazonaws.com/groups/global/AllUsers",
					}],
					"permission": "READ",
				}],
			}],
		},
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
}

test_net004_authenticated_users_grant_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_acl.example",
		"type": "aws_s3_bucket_acl",
		"actions": ["create"],
		"after": {
			"access_control_policy": [{
				"grant": [{
					"grantee": [{
						"type": "Group",
						"uri": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
					}],
					"permission": "READ",
				}],
			}],
		},
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
}

test_net004_legacy_bucket_acl_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket.example",
		"type": "aws_s3_bucket",
		"actions": ["create"],
		"after": {"acl": "public-read"},
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
}

test_net004_legacy_bucket_grant_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket.example",
		"type": "aws_s3_bucket",
		"actions": ["create"],
		"after": {
			"grant": [{
				"grantee": {
					"type": "Group",
					"uri": "http://acs.amazonaws.com/groups/global/AllUsers",
				},
				"permission": "READ",
			}],
		},
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
}

test_net004_unknown_acl_fails_closed if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_acl.example",
		"type": "aws_s3_bucket_acl",
		"actions": ["create"],
		"after": {},
		"after_unknown": {"access_control_policy": true},
	})

	contains(violation.message, "conclusively evaluated")
}

test_net004_delete_only_acl_passes if {
	count(net004_test_evaluate({
		"address": "aws_s3_bucket_acl.example",
		"type": "aws_s3_bucket_acl",
		"actions": ["delete"],
		"before": {"acl": "public-read"},
		"after": null,
		"after_unknown": {},
	})) == 0
}

# Bucket policy tests

test_net004_private_bucket_policy_passes if {
	count(net004_test_evaluate({
		"address": "aws_s3_bucket_policy.example",
		"type": "aws_s3_bucket_policy",
		"actions": ["create"],
		"after": {
			"policy": json.marshal({
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Principal": {
						"AWS": "arn:aws:iam::123456789012:root",
					},
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example/*",
				}],
			}),
		},
		"after_unknown": {},
	})) == 0
}

test_net004_wildcard_bucket_policy_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_policy.example",
		"type": "aws_s3_bucket_policy",
		"actions": ["create"],
		"after": {
			"policy": json.marshal({
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Principal": "*",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example/*",
				}],
			}),
		},
		"after_unknown": {},
	})

	contains(violation.message, "permits public access")
}

test_net004_wildcard_aws_principal_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_policy.example",
		"type": "aws_s3_bucket_policy",
		"actions": ["create"],
		"after": {
			"policy": json.marshal({
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "*"},
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example/*",
				}],
			}),
		},
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
}

test_net004_deny_wildcard_policy_passes if {
	count(net004_test_evaluate({
		"address": "aws_s3_bucket_policy.example",
		"type": "aws_s3_bucket_policy",
		"actions": ["create"],
		"after": {
			"policy": json.marshal({
				"Statement": [{
					"Effect": "Deny",
					"Principal": "*",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example/*",
				}],
			}),
		},
		"after_unknown": {},
	})) == 0
}

test_net004_malformed_bucket_policy_fails_closed if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_policy.example",
		"type": "aws_s3_bucket_policy",
		"actions": ["create"],
		"after": {"policy": "{invalid-json"},
		"after_unknown": {},
	})

	contains(violation.message, "conclusively evaluated")
}

test_net004_unknown_bucket_policy_fails_closed if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_policy.example",
		"type": "aws_s3_bucket_policy",
		"actions": ["create"],
		"after": {},
		"after_unknown": {"policy": true},
	})

	violation.policy_id == "AWS-NET-004"
}

# Public Access Block tests

test_net004_all_bucket_pab_controls_pass if {
	count(net004_test_evaluate({
		"address": "aws_s3_bucket_public_access_block.example",
		"type": "aws_s3_bucket_public_access_block",
		"actions": ["create"],
		"after": net004_test_pab_controls,
		"after_unknown": {},
	})) == 0
}

test_net004_missing_block_public_acls_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_public_access_block.example",
		"type": "aws_s3_bucket_public_access_block",
		"actions": ["create"],
		"after": object.union(net004_test_pab_controls, {
			"block_public_acls": false,
		}),
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
}

test_net004_missing_ignore_public_acls_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_public_access_block.example",
		"type": "aws_s3_bucket_public_access_block",
		"actions": ["create"],
		"after": object.union(net004_test_pab_controls, {
			"ignore_public_acls": false,
		}),
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
}

test_net004_missing_block_public_policy_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_public_access_block.example",
		"type": "aws_s3_bucket_public_access_block",
		"actions": ["create"],
		"after": object.union(net004_test_pab_controls, {
			"block_public_policy": false,
		}),
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
}

test_net004_missing_restrict_public_buckets_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_public_access_block.example",
		"type": "aws_s3_bucket_public_access_block",
		"actions": ["create"],
		"after": object.union(net004_test_pab_controls, {
			"restrict_public_buckets": false,
		}),
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
}

test_net004_account_pab_controls_pass if {
	count(net004_test_evaluate({
		"address": "aws_s3_account_public_access_block.example",
		"type": "aws_s3_account_public_access_block",
		"actions": ["create"],
		"after": net004_test_pab_controls,
		"after_unknown": {},
	})) == 0
}

test_net004_unknown_pab_control_fails_closed if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_public_access_block.example",
		"type": "aws_s3_bucket_public_access_block",
		"actions": ["create"],
		"after": {
			"block_public_acls": true,
			"ignore_public_acls": true,
			"block_public_policy": true,
		},
		"after_unknown": {
			"restrict_public_buckets": true,
		},
	})

	contains(violation.message, "conclusively evaluated")
}

test_net004_delete_only_pab_removal_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_public_access_block.example",
		"type": "aws_s3_bucket_public_access_block",
		"actions": ["delete"],
		"before": net004_test_pab_controls,
		"after": null,
		"after_unknown": {},
	})

	contains(violation.message, "protection is being removed")
}

# Lifecycle tests

test_net004_update_public_acl_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_acl.example",
		"type": "aws_s3_bucket_acl",
		"actions": ["update"],
		"before": {"acl": "private"},
		"after": {"acl": "public-read"},
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
}

test_net004_replacement_public_acl_detected if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_acl.example",
		"type": "aws_s3_bucket_acl",
		"actions": ["delete", "create"],
		"before": {"acl": "private"},
		"after": {"acl": "public-read"},
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
}

test_net004_noop_resource_not_evaluated if {
	count(net004_test_evaluate({
		"address": "aws_s3_bucket_acl.example",
		"type": "aws_s3_bucket_acl",
		"actions": ["no-op"],
		"before": {"acl": "public-read"},
		"after": {"acl": "public-read"},
		"after_unknown": {},
	})) == 0
}

test_net004_unrelated_unknown_attribute_passes if {
	count(net004_test_evaluate({
		"address": "aws_s3_bucket.example",
		"type": "aws_s3_bucket",
		"actions": ["create"],
		"after": {"bucket": "private-example"},
		"after_unknown": {
			"id": true,
			"arn": true,
		},
	})) == 0
}

# Violation contract

test_net004_violation_has_seven_canonical_fields if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_acl.example",
		"type": "aws_s3_bucket_acl",
		"actions": ["create"],
		"after": {"acl": "public-read"},
		"after_unknown": {},
	})

	object.keys(violation) == {
		"policy_id",
		"title",
		"severity",
		"category",
		"resource",
		"message",
		"remediation",
	}
}

test_net004_violation_metadata_is_correct if {
	some violation in net004_test_evaluate({
		"address": "aws_s3_bucket_acl.example",
		"type": "aws_s3_bucket_acl",
		"actions": ["create"],
		"after": {"acl": "public-read"},
		"after_unknown": {},
	})

	violation.policy_id == "AWS-NET-004"
	violation.title == "Prevent Public S3 Bucket Exposure"
	violation.severity == "CRITICAL"
	violation.category == "NETWORK"
	violation.resource == "aws_s3_bucket_acl.example"
	is_string(violation.message)
	is_string(violation.remediation)
}

test_net004_terraform_plan_resource_changes_triggers_deny if {
	plan := {
		"resource_changes": [{
			"address": "aws_s3_bucket_acl.net004_acl",
			"type": "aws_s3_bucket_acl",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {"acl": "public-read"},
				"after_unknown": {},
			},
		}],
	}

	denials := data.main.deny with input as plan
	some denial in denials
	denial.policy_id == "AWS-NET-004"
	denial.msg == "S3 bucket ACL grants public access"
}

test_net004_private_acl_with_unknown_computed_access_policy_passes if {
    count(net004_test_evaluate({
        "address": "aws_s3_bucket_acl.example",
        "type": "aws_s3_bucket_acl",
        "actions": ["create"],
        "after": {
            "acl": "private",
        },
        "after_unknown": {
            "access_control_policy": true,
        },
    })) == 0
}