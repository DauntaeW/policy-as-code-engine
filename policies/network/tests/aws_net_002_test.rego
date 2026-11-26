
package main

import rego.v1

# --------------------------------------------------
# Test helpers
# --------------------------------------------------

net002_policy_violations(plan) := filtered if {
    all := data.main.violations with input as plan

    filtered := {
        violation |
        some violation in all
        violation.policy_id == "AWS-NET-002"
    }
}

net002_make_change(resource_type, address, actions, after) := {
    "address": address,
    "type": resource_type,
    "change": {
        "actions": actions,
        "after": after,
        "after_unknown": {}
    }
}

net002_make_change_with_unknown(
    resource_type,
    address,
    actions,
    after,
    after_unknown
) := {
    "address": address,
    "type": resource_type,
    "change": {
        "actions": actions,
        "after": after,
        "after_unknown": after_unknown
    }
}

net002_make_plan(changes) := {
    "resource_changes": changes
}

# --------------------------------------------------
# Known-value tests
# --------------------------------------------------

# 1. Modern public IPv4 RDP must be denied.
test_public_ipv4_rdp_denied if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 2. Modern public IPv6 RDP must be denied.
test_public_ipv6_rdp_denied if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": null,
            "cidr_ipv6": "::/0"
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 3. Restricted IPv4 RDP must be allowed.
test_restricted_ipv4_rdp_allowed if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": "203.0.113.10/32",
            "cidr_ipv6": null
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 0
}

# 4. Restricted IPv6 RDP must be allowed.
test_restricted_ipv6_rdp_allowed if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": null,
            "cidr_ipv6": "2001:db8::/64"
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 0
}

# 5. TCP range containing port 3389 must be denied.
test_tcp_port_range_containing_rdp_denied if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 3000,
            "to_port": 4000,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 6. TCP range excluding port 3389 must be allowed.
test_tcp_port_range_excluding_rdp_allowed if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 3000,
            "to_port": 3300,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 0
}

# 7. All-protocol public IPv4 ingress must be denied.
test_all_protocol_public_ipv4_denied if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "-1",
            "from_port": null,
            "to_port": null,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 8. All-protocol public IPv6 ingress must be denied.
test_all_protocol_public_ipv6_denied if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "-1",
            "from_port": null,
            "to_port": null,
            "cidr_ipv4": null,
            "cidr_ipv6": "::/0"
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 9. Non-TCP protocols must not trigger the RDP policy.
test_non_tcp_protocol_allowed if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "udp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 0
}

# 10. Inline security group RDP exposure must be denied.
test_inline_public_rdp_denied if {
    plan := net002_make_plan([
        net002_make_change("aws_security_group", "aws_security_group.inline", ["create"], {
            "ingress": [{
                "protocol": "tcp",
                "from_port": 3389,
                "to_port": 3389,
                "cidr_blocks": ["0.0.0.0/0"],
                "ipv6_cidr_blocks": []
            }]
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 11. Legacy standalone RDP exposure must be denied.
test_legacy_public_rdp_denied if {
    plan := net002_make_plan([
        net002_make_change("aws_security_group_rule", "aws_security_group_rule.legacy", ["create"], {
            "type": "ingress",
            "protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_blocks": ["0.0.0.0/0"],
            "ipv6_cidr_blocks": null
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 12. Delete-only changes must not trigger the policy.
test_delete_only_change_allowed if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["delete"], {
            "ip_protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 0
}

# 13. Create operations must be evaluated.
test_create_operation_evaluated if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 14. Update operations must be evaluated.
test_update_operation_evaluated if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["update"], {
            "ip_protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 15. Delete/create replacements must evaluate the planned state.
test_delete_create_replacement_evaluated if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["delete", "create"], {
            "ip_protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 16. Create/delete replacements must evaluate the planned state.
test_create_delete_replacement_evaluated if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create", "delete"], {
            "ip_protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 17. Multiple inline rules must be evaluated independently.
test_multiple_inline_rules_evaluated_independently if {
    plan := net002_make_plan([
        net002_make_change("aws_security_group", "aws_security_group.inline", ["create"], {
            "ingress": [
                {
                    "protocol": "tcp",
                    "from_port": 443,
                    "to_port": 443,
                    "cidr_blocks": ["0.0.0.0/0"],
                    "ipv6_cidr_blocks": []
                },
                {
                    "protocol": "tcp",
                    "from_port": 3389,
                    "to_port": 3389,
                    "cidr_blocks": ["0.0.0.0/0"],
                    "ipv6_cidr_blocks": []
                }
            ]
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# --------------------------------------------------
# Violation contract tests
# --------------------------------------------------

# 18. Every violation must satisfy the seven-field contract.
test_violation_contract if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.contract_test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1

    some violation in actual
    count(object.keys(violation)) == 7

    violation.policy_id == "AWS-NET-002"
    violation.title == "Block Unrestricted RDP Ingress"
    violation.severity == "HIGH"
    violation.category == "NETWORK"
    violation.resource == "aws_vpc_security_group_ingress_rule.contract_test"
    is_string(violation.message)
    is_string(violation.remediation)
}

# 19. Conftest adapter must expose the message as msg.
test_deny_adapter_exposes_msg if {
    plan := net002_make_plan([
        net002_make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.adapter_test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := deny with input as plan
    count(actual) == 1

    some result in actual
    result.msg == result.message
}

# --------------------------------------------------
# Unknown-value tests
# --------------------------------------------------

# 20. Unknown protocol with a public source must be denied.
test_unknown_protocol_with_public_source_denied if {
    plan := net002_make_plan([
        net002_make_change_with_unknown(
            "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_ingress_rule.unknown_protocol",
            ["create"],
            {
                "ip_protocol": null,
                "from_port": 3389,
                "to_port": 3389,
                "cidr_ipv4": "0.0.0.0/0",
                "cidr_ipv6": null
            },
            {"ip_protocol": true}
        )
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 21. Unknown TCP port with a public source must be denied.
test_unknown_tcp_port_with_public_source_denied if {
    plan := net002_make_plan([
        net002_make_change_with_unknown(
            "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_ingress_rule.unknown_port",
            ["create"],
            {
                "ip_protocol": "tcp",
                "from_port": null,
                "to_port": 3389,
                "cidr_ipv4": "0.0.0.0/0",
                "cidr_ipv6": null
            },
            {"from_port": true}
        )
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 22. Unknown CIDR with known TCP/3389 must be denied.
test_unknown_public_cidr_denied if {
    plan := net002_make_plan([
        net002_make_change_with_unknown(
            "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_ingress_rule.unknown_cidr",
            ["create"],
            {
                "ip_protocol": "tcp",
                "from_port": 3389,
                "to_port": 3389,
                "cidr_ipv4": null,
                "cidr_ipv6": null
            },
            {"cidr_ipv4": true}
        )
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 1
}

# 23. Known restricted CIDR with unrelated unknown values must pass.
test_restricted_cidr_with_unrelated_unknown_allowed if {
    plan := net002_make_plan([
        net002_make_change_with_unknown(
            "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_ingress_rule.unknown_id",
            ["create"],
            {
                "ip_protocol": "tcp",
                "from_port": 3389,
                "to_port": 3389,
                "cidr_ipv4": "203.0.113.10/32",
                "cidr_ipv6": null
            },
            {"security_group_id": true}
        )
    ])

    actual := net002_policy_violations(plan)
    count(actual) == 0
}
