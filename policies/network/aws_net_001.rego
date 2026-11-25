package main

import rego.v1

# AWS-NET-001: Block unrestricted SSH ingress.

# --------------------------------------------------
# Known-value helpers
# --------------------------------------------------

allows_ssh(protocol, _, _) if {
    protocol == "-1"
}

allows_ssh(protocol, from_port, to_port) if {
    protocol in {"tcp", "6"}
    is_number(from_port)
    is_number(to_port)
    from_port <= 22
    to_port >= 22
}

is_active(resource_change) if {
    some action in resource_change.change.actions
    action in {"create", "update"}
}

# --------------------------------------------------
# Unknown-value helpers
# --------------------------------------------------

is_unknown(after_unknown, attribute) := (
    object.get(after_unknown, attribute, false) == true
)

# At least one security-relevant attribute must be unknown.
has_unknown_security_attribute(
    protocol_unknown,
    from_unknown,
    to_unknown,
    ipv4_unknown,
    ipv6_unknown
) := (
    true in [
        protocol_unknown,
        from_unknown,
        to_unknown,
        ipv4_unknown,
        ipv6_unknown
    ]
)

# Unknown protocol could represent TCP or all protocols.
could_be_ssh(_, _, _, true, _, _) := true if {
    true
}

# All-protocol rules include SSH regardless of port values.
could_be_ssh(protocol, _, _, _, _, _) := true if {
    protocol == "-1"
}

# TCP with both ports unknown could include port 22.
could_be_ssh(protocol, _, _, _, true, true) := true if {
    protocol in {"tcp", "6"}
}

# Unknown starting port, known ending port permits port 22.
could_be_ssh(protocol, _, to_port, _, true, false) := true if {
    protocol in {"tcp", "6"}
    is_number(to_port)
    to_port >= 22
}

# Unknown ending port, known starting port permits port 22.
could_be_ssh(protocol, from_port, _, _, false, true) := true if {
    protocol in {"tcp", "6"}
    is_number(from_port)
    from_port <= 22
}

# Both ports known: determine whether the range includes port 22.
could_be_ssh(protocol, from_port, to_port, _, false, false) := true if {
    protocol in {"tcp", "6"}
    is_number(from_port)
    is_number(to_port)
    from_port <= 22
    to_port >= 22
}

# Return true when an array contains a specified value.
default contains_value(_, _) := false

contains_value(values, expected) := true if {
    is_array(values)
    expected in values
}

# Detect unknown elements in a Terraform collection.
default has_unknown_collection_element(_, _) := false

has_unknown_collection_element(after_unknown, attribute) := true if {
    object.get(after_unknown, attribute, false) == true
}

has_unknown_collection_element(after_unknown, attribute) := true if {
    values := object.get(after_unknown, attribute, [])
    is_array(values)
    true in values
}

# Inline ingress rules represent unknown values as nested objects.
inline_rule_unknown(unknown_rule, attribute) := (
    object.get(unknown_rule, attribute, false) == true
)

# Inline CIDR collections can contain unknown elements.
default inline_cidr_unknown(_, _) := false

inline_cidr_unknown(unknown_rule, attribute) := true if {
    object.get(unknown_rule, attribute, false) == true
}

inline_cidr_unknown(unknown_rule, attribute) := true if {
    values := object.get(unknown_rule, attribute, [])
    is_array(values)
    true in values
}

# Potentially public inline ingress source.
potentially_public_inline(rule, unknown_rule) := (
    true in [
        contains_value(
            object.get(rule, "cidr_blocks", []),
            "0.0.0.0/0"
        ),
        contains_value(
            object.get(rule, "ipv6_cidr_blocks", []),
            "::/0"
        ),
        inline_cidr_unknown(unknown_rule, "cidr_blocks"),
        inline_cidr_unknown(unknown_rule, "ipv6_cidr_blocks")
    ]
)

# Potentially public legacy ingress source.
potentially_public_legacy(after, after_unknown) := (
    true in [
        contains_value(
            object.get(after, "cidr_blocks", []),
            "0.0.0.0/0"
        ),
        contains_value(
            object.get(after, "ipv6_cidr_blocks", []),
            "::/0"
        ),
        has_unknown_collection_element(after_unknown, "cidr_blocks"),
        has_unknown_collection_element(after_unknown, "ipv6_cidr_blocks")
    ]
)

# Potentially public modern ingress source.
potentially_public(after, ipv4_unknown, ipv6_unknown) := (
    true in [
        object.get(after, "cidr_ipv4", null) == "0.0.0.0/0",
        object.get(after, "cidr_ipv6", null) == "::/0",
        ipv4_unknown,
        ipv6_unknown
    ]
)

# Standardized violation for unresolved SSH exposure.
unknown_ssh_violation(rc) := {
    "policy_id": "AWS-NET-001",
    "title": "Unrestricted SSH ingress",
    "severity": "HIGH",
    "category": "NETWORK",
    "resource": rc.address,
    "message": "SSH exposure could not be verified because one or more security-relevant ingress attributes are unknown at plan time.",
    "remediation": "Make the SSH protocol, port range, and source CIDR values known during planning, then restrict SSH access to approved trusted CIDR ranges."
}

# --------------------------------------------------
# Inline rules: aws_security_group
# --------------------------------------------------

# Known-value IPv4 exposure.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_security_group"
    is_active(rc)

    some rule in rc.change.after.ingress
    allows_ssh(rule.protocol, rule.from_port, rule.to_port)

    some cidr in object.get(rule, "cidr_blocks", [])
    cidr == "0.0.0.0/0"

    violation := {
        "policy_id": "AWS-NET-001",
        "title": "Unrestricted SSH ingress",
        "severity": "HIGH",
        "category": "NETWORK",
        "resource": rc.address,
        "message": "SSH ingress is allowed from 0.0.0.0/0.",
        "remediation": "Restrict SSH access to approved trusted IPv4 CIDR ranges."
    }
}

# Known-value IPv6 exposure.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_security_group"
    is_active(rc)

    some rule in rc.change.after.ingress
    allows_ssh(rule.protocol, rule.from_port, rule.to_port)

    some cidr in object.get(rule, "ipv6_cidr_blocks", [])
    cidr == "::/0"

    violation := {
        "policy_id": "AWS-NET-001",
        "title": "Unrestricted SSH ingress",
        "severity": "HIGH",
        "category": "NETWORK",
        "resource": rc.address,
        "message": "SSH ingress is allowed from ::/0.",
        "remediation": "Restrict SSH access to approved trusted IPv6 CIDR ranges."
    }
}

# Unknown values: inline ingress rules.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_security_group"
    is_active(rc)

    after := rc.change.after
    unknown := object.get(rc.change, "after_unknown", {})

    ingress := object.get(after, "ingress", [])
    unknown_ingress := object.get(unknown, "ingress", [])

    is_array(ingress)
    is_array(unknown_ingress)

    some i
    rule := ingress[i]
    unknown_rule := unknown_ingress[i]

    protocol_unknown := inline_rule_unknown(unknown_rule, "protocol")
    from_unknown := inline_rule_unknown(unknown_rule, "from_port")
    to_unknown := inline_rule_unknown(unknown_rule, "to_port")

    ipv4_unknown := inline_cidr_unknown(unknown_rule, "cidr_blocks")
    ipv6_unknown := inline_cidr_unknown(unknown_rule, "ipv6_cidr_blocks")

    has_unknown_security_attribute(
        protocol_unknown,
        from_unknown,
        to_unknown,
        ipv4_unknown,
        ipv6_unknown
    )

    potentially_public_inline(rule, unknown_rule)

    potentially_ssh := could_be_ssh(
        rule.protocol,
        rule.from_port,
        rule.to_port,
        protocol_unknown,
        from_unknown,
        to_unknown
    )

    potentially_ssh

    violation := unknown_ssh_violation(rc)
}

# --------------------------------------------------
# Modern rules: aws_vpc_security_group_ingress_rule
# --------------------------------------------------

# Known-value IPv4 exposure.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_vpc_security_group_ingress_rule"
    is_active(rc)

    after := rc.change.after
    allows_ssh(after.ip_protocol, after.from_port, after.to_port)

    after.cidr_ipv4 == "0.0.0.0/0"

    violation := {
        "policy_id": "AWS-NET-001",
        "title": "Unrestricted SSH ingress",
        "severity": "HIGH",
        "category": "NETWORK",
        "resource": rc.address,
        "message": "SSH ingress is allowed from 0.0.0.0/0.",
        "remediation": "Restrict SSH access to approved trusted IPv4 CIDR ranges."
    }
}

# Known-value IPv6 exposure.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_vpc_security_group_ingress_rule"
    is_active(rc)

    after := rc.change.after
    allows_ssh(after.ip_protocol, after.from_port, after.to_port)

    after.cidr_ipv6 == "::/0"

    violation := {
        "policy_id": "AWS-NET-001",
        "title": "Unrestricted SSH ingress",
        "severity": "HIGH",
        "category": "NETWORK",
        "resource": rc.address,
        "message": "SSH ingress is allowed from ::/0.",
        "remediation": "Restrict SSH access to approved trusted IPv6 CIDR ranges."
    }
}

# Unknown values: modern ingress rules.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_vpc_security_group_ingress_rule"
    is_active(rc)

    after := rc.change.after
    unknown := object.get(rc.change, "after_unknown", {})

    protocol_unknown := is_unknown(unknown, "ip_protocol")
    from_unknown := is_unknown(unknown, "from_port")
    to_unknown := is_unknown(unknown, "to_port")

    ipv4_unknown := is_unknown(unknown, "cidr_ipv4")
    ipv6_unknown := is_unknown(unknown, "cidr_ipv6")

    has_unknown_security_attribute(
        protocol_unknown,
        from_unknown,
        to_unknown,
        ipv4_unknown,
        ipv6_unknown
    )

    potentially_public(after, ipv4_unknown, ipv6_unknown)

    potentially_ssh := could_be_ssh(
        after.ip_protocol,
        after.from_port,
        after.to_port,
        protocol_unknown,
        from_unknown,
        to_unknown
    )

    potentially_ssh

    violation := unknown_ssh_violation(rc)
}

# --------------------------------------------------
# Legacy rules: aws_security_group_rule
# --------------------------------------------------

# Known-value IPv4 exposure.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_security_group_rule"
    is_active(rc)

    after := rc.change.after
    after.type == "ingress"

    allows_ssh(after.protocol, after.from_port, after.to_port)

    some cidr in object.get(after, "cidr_blocks", [])
    cidr == "0.0.0.0/0"

    violation := {
        "policy_id": "AWS-NET-001",
        "title": "Unrestricted SSH ingress",
        "severity": "HIGH",
        "category": "NETWORK",
        "resource": rc.address,
        "message": "SSH ingress is allowed from 0.0.0.0/0.",
        "remediation": "Restrict SSH access to approved trusted IPv4 CIDR ranges."
    }
}

# Known-value IPv6 exposure.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_security_group_rule"
    is_active(rc)

    after := rc.change.after
    after.type == "ingress"

    allows_ssh(after.protocol, after.from_port, after.to_port)

    some cidr in object.get(after, "ipv6_cidr_blocks", [])
    cidr == "::/0"

    violation := {
        "policy_id": "AWS-NET-001",
        "title": "Unrestricted SSH ingress",
        "severity": "HIGH",
        "category": "NETWORK",
        "resource": rc.address,
        "message": "SSH ingress is allowed from ::/0.",
        "remediation": "Restrict SSH access to approved trusted IPv6 CIDR ranges."
    }
}

# Unknown values: legacy standalone ingress rules.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_security_group_rule"
    is_active(rc)

    after := rc.change.after
    after.type == "ingress"

    unknown := object.get(rc.change, "after_unknown", {})

    protocol_unknown := is_unknown(unknown, "protocol")
    from_unknown := is_unknown(unknown, "from_port")
    to_unknown := is_unknown(unknown, "to_port")

    ipv4_unknown := has_unknown_collection_element(
        unknown,
        "cidr_blocks"
    )

    ipv6_unknown := has_unknown_collection_element(
        unknown,
        "ipv6_cidr_blocks"
    )

    has_unknown_security_attribute(
        protocol_unknown,
        from_unknown,
        to_unknown,
        ipv4_unknown,
        ipv6_unknown
    )

    potentially_public_legacy(after, unknown)

    potentially_ssh := could_be_ssh(
        after.protocol,
        after.from_port,
        after.to_port,
        protocol_unknown,
        from_unknown,
        to_unknown
    )

    potentially_ssh

    violation := unknown_ssh_violation(rc)
}

# --------------------------------------------------
# Conftest adapter
# --------------------------------------------------

deny contains result if {
    some violation in violations

    result := object.union(
        violation,
        {"msg": violation.message}
    )
}