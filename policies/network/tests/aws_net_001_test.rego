package main

import rego.v1

# --------------------------------------------------
# Test helpers
# --------------------------------------------------

make_change(resource_type, address, actions, after) := {
    "address": address,
    "type": resource_type,
    "change": {
        "actions": actions,
        "after": after,
        "after_unknown": {}
    }
}

make_change_with_unknown(
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

make_plan(changes) := {
    "resource_changes": changes
}

# --------------------------------------------------
# Known-value tests
# --------------------------------------------------

# 1. Inline security group: public IPv4 SSH must be denied.
test_inline_public_ipv4_ssh_denied if {
    plan := make_plan([
        make_change("aws_security_group", "aws_security_group.test", ["create"], {
            "ingress": [{
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["0.0.0.0/0"],
                "ipv6_cidr_blocks": []
            }]
        })
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 2. Inline security group: public IPv6 SSH must be denied.
test_inline_public_ipv6_ssh_denied if {
    plan := make_plan([
        make_change("aws_security_group", "aws_security_group.test", ["create"], {
            "ingress": [{
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": [],
                "ipv6_cidr_blocks": ["::/0"]
            }]
        })
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 3. Modern rule: public IPv4 SSH must be denied.
test_modern_public_ipv4_ssh_denied if {
    plan := make_plan([
        make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 4. Modern rule: public IPv6 SSH must be denied.
test_modern_public_ipv6_ssh_denied if {
    plan := make_plan([
        make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_ipv4": null,
            "cidr_ipv6": "::/0"
        })
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 5. Legacy rule: public IPv4 SSH must be denied.
test_legacy_public_ipv4_ssh_denied if {
    plan := make_plan([
        make_change("aws_security_group_rule", "aws_security_group_rule.test", ["create"], {
            "type": "ingress",
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_blocks": ["0.0.0.0/0"],
            "ipv6_cidr_blocks": null
        })
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 6. Legacy rule: public IPv6 SSH must be denied.
test_legacy_public_ipv6_ssh_denied if {
    plan := make_plan([
        make_change("aws_security_group_rule", "aws_security_group_rule.test", ["create"], {
            "type": "ingress",
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_blocks": null,
            "ipv6_cidr_blocks": ["::/0"]
        })
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 7. Restricted IPv4 CIDR must be allowed.
test_restricted_ipv4_cidr_allowed if {
    plan := make_plan([
        make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_ipv4": "203.0.113.10/32",
            "cidr_ipv6": null
        })
    ])

    actual := violations with input as plan
    count(actual) == 0
}

# 8. A different TCP port must be allowed.
test_non_ssh_port_allowed if {
    plan := make_plan([
        make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 443,
            "to_port": 443,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := violations with input as plan
    count(actual) == 0
}

# 9. Legacy egress must not trigger the ingress policy.
test_egress_rule_allowed if {
    plan := make_plan([
        make_change("aws_security_group_rule", "aws_security_group_rule.test", ["create"], {
            "type": "egress",
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_blocks": ["0.0.0.0/0"],
            "ipv6_cidr_blocks": null
        })
    ])

    actual := violations with input as plan
    count(actual) == 0
}

# 10. Delete-only changes must not trigger the policy.
test_delete_only_change_allowed if {
    plan := make_plan([
        make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["delete"], {
            "ip_protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := violations with input as plan
    count(actual) == 0
}

# 11. A TCP range containing port 22 must be denied.
test_tcp_port_range_containing_ssh_denied if {
    plan := make_plan([
        make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 20,
            "to_port": 25,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 12. All-protocol public ingress must be denied.
test_all_protocol_public_ingress_denied if {
    plan := make_plan([
        make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "-1",
            "from_port": null,
            "to_port": null,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 13. Numeric TCP protocol identifier must be denied.
test_numeric_tcp_protocol_denied if {
    plan := make_plan([
        make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.test", ["create"], {
            "ip_protocol": "6",
            "from_port": 22,
            "to_port": 22,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 14. Every violation must satisfy the seven-field contract.
test_violation_contract if {
    plan := make_plan([
        make_change("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_ingress_rule.contract_test", ["create"], {
            "ip_protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_ipv4": "0.0.0.0/0",
            "cidr_ipv6": null
        })
    ])

    actual := violations with input as plan
    count(actual) == 1

    some violation in actual
    count(object.keys(violation)) == 7

    violation.policy_id == "AWS-NET-001"
    violation.severity == "HIGH"
    violation.category == "NETWORK"
    violation.resource == "aws_vpc_security_group_ingress_rule.contract_test"
}

# --------------------------------------------------
# Modern unknown-value tests
# --------------------------------------------------

# 15. Unknown protocol with a public IPv4 source must be denied.
test_unknown_protocol_with_public_ipv4_denied if {
    plan := make_plan([
        make_change_with_unknown(
            "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_ingress_rule.unknown_protocol",
            ["create"],
            {
                "ip_protocol": null,
                "from_port": 22,
                "to_port": 22,
                "cidr_ipv4": "0.0.0.0/0",
                "cidr_ipv6": null
            },
            {"ip_protocol": true}
        )
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 16. Unknown port with known TCP protocol and public IPv4 must be denied.
test_unknown_port_with_public_ipv4_denied if {
    plan := make_plan([
        make_change_with_unknown(
            "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_ingress_rule.unknown_port",
            ["create"],
            {
                "ip_protocol": "tcp",
                "from_port": null,
                "to_port": 22,
                "cidr_ipv4": "0.0.0.0/0",
                "cidr_ipv6": null
            },
            {"from_port": true}
        )
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 17. Unknown IPv4 source with known TCP/22 must be denied.
test_unknown_ipv4_cidr_denied if {
    plan := make_plan([
        make_change_with_unknown(
            "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_ingress_rule.unknown_ipv4",
            ["create"],
            {
                "ip_protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr_ipv4": null,
                "cidr_ipv6": null
            },
            {"cidr_ipv4": true}
        )
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 18. Unknown IPv6 source with known TCP/22 must be denied.
test_unknown_ipv6_cidr_denied if {
    plan := make_plan([
        make_change_with_unknown(
            "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_ingress_rule.unknown_ipv6",
            ["create"],
            {
                "ip_protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr_ipv4": null,
                "cidr_ipv6": null
            },
            {"cidr_ipv6": true}
        )
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 19. Unknown unrelated attributes must not trigger NET-001.
test_unknown_unrelated_attribute_allowed if {
    plan := make_plan([
        make_change_with_unknown(
            "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_ingress_rule.unknown_id",
            ["create"],
            {
                "ip_protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr_ipv4": "203.0.113.10/32",
                "cidr_ipv6": null
            },
            {"security_group_id": true}
        )
    ])

    actual := violations with input as plan
    count(actual) == 0
}

# --------------------------------------------------
# Inline unknown-value tests
# --------------------------------------------------

# 20. Inline unknown protocol with public IPv4 must be denied.
test_inline_unknown_protocol_denied if {
    plan := make_plan([
        make_change_with_unknown(
            "aws_security_group",
            "aws_security_group.inline_unknown_protocol",
            ["create"],
            {
                "ingress": [{
                    "protocol": null,
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"],
                    "ipv6_cidr_blocks": []
                }]
            },
            {
                "ingress": [{
                    "protocol": true,
                    "from_port": false,
                    "to_port": false,
                    "cidr_blocks": [false],
                    "ipv6_cidr_blocks": []
                }]
            }
        )
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 21. Inline unknown IPv6 CIDR must be denied.
test_inline_unknown_ipv6_cidr_denied if {
    plan := make_plan([
        make_change_with_unknown(
            "aws_security_group",
            "aws_security_group.inline_unknown_ipv6",
            ["create"],
            {
                "ingress": [{
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": [],
                    "ipv6_cidr_blocks": [null]
                }]
            },
            {
                "ingress": [{
                    "cidr_blocks": [],
                    "ipv6_cidr_blocks": [true]
                }]
            }
        )
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 22. Inline unknown port with public IPv4 must be denied.
test_inline_unknown_port_denied if {
    plan := make_plan([
        make_change_with_unknown(
            "aws_security_group",
            "aws_security_group.inline_unknown_port",
            ["create"],
            {
                "ingress": [{
                    "protocol": "tcp",
                    "from_port": null,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"],
                    "ipv6_cidr_blocks": []
                }]
            },
            {
                "ingress": [{
                    "from_port": true
                }]
            }
        )
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 23. Unknown unrelated inline attributes must not trigger NET-001.
test_inline_unknown_unrelated_attribute_allowed if {
    plan := make_plan([
        make_change_with_unknown(
            "aws_security_group",
            "aws_security_group.inline_unknown_description",
            ["create"],
            {
                "ingress": [{
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "description": null,
                    "cidr_blocks": ["203.0.113.10/32"],
                    "ipv6_cidr_blocks": []
                }]
            },
            {
                "ingress": [{
                    "description": true,
                    "cidr_blocks": [false],
                    "ipv6_cidr_blocks": []
                }]
            }
        )
    ])

    actual := violations with input as plan
    count(actual) == 0
}

# --------------------------------------------------
# Legacy unknown-value tests
# --------------------------------------------------

# 24. Legacy unknown protocol with public IPv4 must be denied.
test_legacy_unknown_protocol_denied if {
    plan := make_plan([
        make_change_with_unknown(
            "aws_security_group_rule",
            "aws_security_group_rule.unknown_protocol",
            ["create"],
            {
                "type": "ingress",
                "protocol": null,
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["0.0.0.0/0"],
                "ipv6_cidr_blocks": null
            },
            {"protocol": true}
        )
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 25. Legacy unknown IPv4 CIDR must be denied.
test_legacy_unknown_ipv4_cidr_denied if {
    plan := make_plan([
        make_change_with_unknown(
            "aws_security_group_rule",
            "aws_security_group_rule.unknown_ipv4",
            ["create"],
            {
                "type": "ingress",
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": [null],
                "ipv6_cidr_blocks": null
            },
            {"cidr_blocks": [true]}
        )
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 26. Legacy unknown port with public IPv6 must be denied.
test_legacy_unknown_port_denied if {
    plan := make_plan([
        make_change_with_unknown(
            "aws_security_group_rule",
            "aws_security_group_rule.unknown_port",
            ["create"],
            {
                "type": "ingress",
                "protocol": "tcp",
                "from_port": 22,
                "to_port": null,
                "cidr_blocks": null,
                "ipv6_cidr_blocks": ["::/0"]
            },
            {"to_port": true}
        )
    ])

    actual := violations with input as plan
    count(actual) == 1
}

# 27. Unknown legacy egress attributes must not trigger NET-001.
test_legacy_unknown_egress_allowed if {
    plan := make_plan([
        make_change_with_unknown(
            "aws_security_group_rule",
            "aws_security_group_rule.unknown_egress",
            ["create"],
            {
                "type": "egress",
                "protocol": null,
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["0.0.0.0/0"],
                "ipv6_cidr_blocks": null
            },
            {"protocol": true}
        )
    ])

    actual := violations with input as plan
    count(actual) == 0
}