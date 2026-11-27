
package main

import rego.v1

# ------------------------------------------------------------
# Test fixtures and helpers
# ------------------------------------------------------------

net003_test_plan(resource_type, address, after, unknown, actions) := {
	"resource_changes": [{
		"address": address,
		"type": resource_type,
		"change": {
			"actions": actions,
			"after": after,
			"after_unknown": unknown,
		},
	}],
}

net003_test_inline_plan(rule, unknown, actions) := net003_test_plan(
	"aws_security_group",
	"aws_security_group.test",
	{"ingress": [rule]},
	{"ingress": [unknown]},
	actions,
)

net003_test_legacy_plan(rule, unknown, actions) := net003_test_plan(
	"aws_security_group_rule",
	"aws_security_group_rule.test",
	object.union({"type": "ingress"}, rule),
	unknown,
	actions,
)

net003_test_modern_plan(rule, unknown, actions) := net003_test_plan(
	"aws_vpc_security_group_ingress_rule",
	"aws_vpc_security_group_ingress_rule.test",
	rule,
	unknown,
	actions,
)

net003_test_violations(plan) := result if {
	result := data.main.violations with input as plan
}

net003_test_policy_violations(plan) := [
	violation |
	some violation in net003_test_violations(plan)
	violation.policy_id == "AWS-NET-003"
]

net003_test_count(plan) := count(
	net003_test_policy_violations(plan),
)

# ------------------------------------------------------------
# Confirmed exposure tests
# ------------------------------------------------------------

test_net003_inline_ipv4_postgresql if {
	rule := {
		"protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": ["0.0.0.0/0"],
		"ipv6_cidr_blocks": [],
	}

	plan := net003_test_inline_plan(rule, {}, ["create"])

	net003_test_count(plan) == 1
}

test_net003_legacy_ipv6_mysql if {
	rule := {
		"protocol": "tcp",
		"from_port": 3306,
		"to_port": 3306,
		"cidr_blocks": [],
		"ipv6_cidr_blocks": ["::/0"],
	}

	plan := net003_test_legacy_plan(rule, {}, ["create"])

	net003_test_count(plan) == 1
}

test_net003_modern_ipv4_sqlserver if {
	rule := {
		"ip_protocol": "tcp",
		"from_port": 1433,
		"to_port": 1433,
		"cidr_ipv4": "0.0.0.0/0",
		"cidr_ipv6": null,
	}

	plan := net003_test_modern_plan(rule, {}, ["create"])

	net003_test_count(plan) == 1
}

test_net003_wide_port_range_detects_all_database_ports if {
	rule := {
		"protocol": "tcp",
		"from_port": 1000,
		"to_port": 6000,
		"cidr_blocks": ["0.0.0.0/0"],
		"ipv6_cidr_blocks": [],
	}

	plan := net003_test_inline_plan(rule, {}, ["create"])

	net003_test_count(plan) == 3
}

test_net003_all_protocols_public_ingress_blocked if {
	rule := {
		"protocol": "-1",
		"from_port": 0,
		"to_port": 0,
		"cidr_blocks": ["0.0.0.0/0"],
		"ipv6_cidr_blocks": [],
	}

	plan := net003_test_inline_plan(rule, {}, ["create"])

	net003_test_count(plan) == 3
}

# ------------------------------------------------------------
# Safe configuration tests
# ------------------------------------------------------------

test_net003_udp_database_port_allowed if {
	rule := {
		"protocol": "udp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": ["0.0.0.0/0"],
		"ipv6_cidr_blocks": [],
	}

	plan := net003_test_inline_plan(rule, {}, ["create"])

	net003_test_count(plan) == 0
}

test_net003_restricted_ipv4_source_allowed if {
	rule := {
		"protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": ["10.20.0.0/16"],
		"ipv6_cidr_blocks": [],
	}

	plan := net003_test_inline_plan(rule, {}, ["create"])

	net003_test_count(plan) == 0
}

test_net003_restricted_ipv6_source_allowed if {
	rule := {
		"protocol": "tcp",
		"from_port": 3306,
		"to_port": 3306,
		"cidr_blocks": [],
		"ipv6_cidr_blocks": ["2001:db8::/64"],
	}

	plan := net003_test_inline_plan(rule, {}, ["create"])

	net003_test_count(plan) == 0
}

test_net003_legacy_egress_rule_ignored if {
	rule := {
		"type": "egress",
		"protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": ["0.0.0.0/0"],
		"ipv6_cidr_blocks": [],
	}

	plan := net003_test_plan(
		"aws_security_group_rule",
		"aws_security_group_rule.egress_test",
		rule,
		{},
		["create"],
	)

	net003_test_count(plan) == 0
}

# ------------------------------------------------------------
# Terraform action tests
# ------------------------------------------------------------

test_net003_update_action_evaluated if {
	rule := {
		"ip_protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_ipv4": "0.0.0.0/0",
	}

	plan := net003_test_modern_plan(rule, {}, ["update"])

	net003_test_count(plan) == 1
}

test_net003_delete_create_replacement_evaluated if {
	rule := {
		"ip_protocol": "tcp",
		"from_port": 3306,
		"to_port": 3306,
		"cidr_ipv4": "0.0.0.0/0",
	}

	plan := net003_test_modern_plan(rule, {}, ["delete", "create"])

	net003_test_count(plan) == 1
}

test_net003_create_delete_replacement_evaluated if {
	rule := {
		"ip_protocol": "tcp",
		"from_port": 3306,
		"to_port": 3306,
		"cidr_ipv4": "0.0.0.0/0",
	}

	plan := net003_test_modern_plan(rule, {}, ["create", "delete"])

	net003_test_count(plan) == 1
}

test_net003_delete_only_ignored if {
	rule := {
		"ip_protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_ipv4": "0.0.0.0/0",
	}

	plan := net003_test_modern_plan(rule, {}, ["delete"])

	net003_test_count(plan) == 0
}

test_net003_noop_ignored if {
	rule := {
		"ip_protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_ipv4": "0.0.0.0/0",
	}

	plan := net003_test_modern_plan(rule, {}, ["no-op"])

	net003_test_count(plan) == 0
}

# ------------------------------------------------------------
# Unknown protocol tests
# ------------------------------------------------------------

test_net003_unknown_protocol_blocks_public_database_rule if {
	rule := {
		"protocol": null,
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": ["0.0.0.0/0"],
		"ipv6_cidr_blocks": [],
	}

	unknown := {
		"protocol": true,
	}

	plan := net003_test_inline_plan(rule, unknown, ["create"])

	net003_test_count(plan) == 1
}

# ------------------------------------------------------------
# Unknown port tests
# ------------------------------------------------------------

test_net003_unknown_from_port_blocks_public_database_rule if {
	rule := {
		"protocol": "tcp",
		"from_port": null,
		"to_port": 5432,
		"cidr_blocks": ["0.0.0.0/0"],
		"ipv6_cidr_blocks": [],
	}

	unknown := {
		"from_port": true,
	}

	plan := net003_test_inline_plan(rule, unknown, ["create"])

	net003_test_count(plan) == 3
}

test_net003_unknown_to_port_blocks_public_database_rule if {
	rule := {
		"protocol": "tcp",
		"from_port": 3306,
		"to_port": null,
		"cidr_blocks": ["0.0.0.0/0"],
		"ipv6_cidr_blocks": [],
	}

	unknown := {
		"to_port": true,
	}

	plan := net003_test_inline_plan(rule, unknown, ["create"])

	net003_test_count(plan) == 2
}

# ------------------------------------------------------------
# Unknown CIDR tests
# ------------------------------------------------------------

test_net003_unknown_ipv4_cidr_blocks_public_database_rule if {
	rule := {
		"protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": null,
		"ipv6_cidr_blocks": [],
	}

	unknown := {
		"cidr_blocks": true,
	}

	plan := net003_test_inline_plan(rule, unknown, ["create"])

	net003_test_count(plan) == 1
}

test_net003_unknown_ipv6_cidr_blocks_public_database_rule if {
	rule := {
		"protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": [],
		"ipv6_cidr_blocks": null,
	}

	unknown := {
		"ipv6_cidr_blocks": true,
	}

	plan := net003_test_inline_plan(rule, unknown, ["create"])

	net003_test_count(plan) == 1
}

# ------------------------------------------------------------
# Unknown unrelated attribute tests
# ------------------------------------------------------------

test_net003_unknown_unrelated_attribute_does_not_block if {
	rule := {
		"protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": ["10.20.0.0/16"],
		"ipv6_cidr_blocks": [],
	}

	unknown := {
		"description": true,
	}

	plan := net003_test_inline_plan(rule, unknown, ["create"])

	net003_test_count(plan) == 0
}

test_net003_confirmed_exposure_takes_precedence_over_unrelated_unknown if {
	rule := {
		"protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": ["0.0.0.0/0"],
		"ipv6_cidr_blocks": [],
	}

	unknown := {
		"description": true,
	}

	plan := net003_test_inline_plan(rule, unknown, ["create"])

	net003_test_count(plan) == 1
}

# ------------------------------------------------------------
# Violation contract tests
# ------------------------------------------------------------

test_net003_violation_has_exactly_seven_fields if {
	rule := {
		"protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": ["0.0.0.0/0"],
		"ipv6_cidr_blocks": [],
	}

	plan := net003_test_inline_plan(rule, {}, ["create"])

	violations := net003_test_policy_violations(plan)
	count(violations) == 1

	violation := violations[0]

	count(object.keys(violation)) == 7

	object.keys(violation) == {
		"category",
		"message",
		"policy_id",
		"remediation",
		"resource",
		"severity",
		"title",
	}

	violation.policy_id == "AWS-NET-003"
	violation.severity == "HIGH"
	violation.category == "NETWORK"
}

test_net003_deny_adapter_exposes_msg if {
	rule := {
		"protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": ["0.0.0.0/0"],
		"ipv6_cidr_blocks": [],
	}

	plan := net003_test_inline_plan(rule, {}, ["create"])

	denials := data.main.deny with input as plan

	some denial in denials
	denial.policy_id == "AWS-NET-003"
	denial.msg == denial.message
}
