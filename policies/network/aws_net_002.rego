
package main

import rego.v1

# AWS-NET-002
# Block Unrestricted RDP Ingress
#
# Severity: HIGH
# Category: NETWORK
# Protected port: TCP 3389
#
# Resource representations:
# - aws_security_group
# - aws_security_group_rule
# - aws_vpc_security_group_ingress_rule

# --------------------------------------------------
# Known-value helpers
# --------------------------------------------------

net002_is_active(resource_change) if {
    some action in resource_change.change.actions
    action in {"create", "update"}
}

allows_rdp(protocol, _, _) if {
    protocol == "-1"
}

allows_rdp(protocol, from_port, to_port) if {
    protocol in {"tcp", "6", 6}
    is_number(from_port)
    is_number(to_port)
    from_port <= 3389
    to_port >= 3389
}

default net002_contains_value(_, _) := false

net002_contains_value(values, expected) := true if {
    is_array(values)
    expected in values
}

# --------------------------------------------------
# Unknown-value helpers
# --------------------------------------------------

net002_is_unknown(after_unknown, attribute) := (
    object.get(after_unknown, attribute, false) == true
)

default net002_has_unknown_collection_element(_, _) := false

net002_has_unknown_collection_element(after_unknown, attribute) := true if {
    object.get(after_unknown, attribute, false) == true
}

net002_has_unknown_collection_element(after_unknown, attribute) := true if {
    values := object.get(after_unknown, attribute, [])
    is_array(values)
    true in values
}

default net002_inline_cidr_unknown(_, _) := false

net002_inline_cidr_unknown(unknown_rule, attribute) := true if {
    object.get(unknown_rule, attribute, false) == true
}

net002_inline_cidr_unknown(unknown_rule, attribute) := true if {
    values := object.get(unknown_rule, attribute, [])
    is_array(values)
    true in values
}

net002_has_unknown_security_attribute(
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
could_be_rdp(_, _, _, true, _, _) := true if {
    true
}

# All-protocol rules include RDP regardless of port values.
could_be_rdp(protocol, _, _, _, _, _) := true if {
    protocol == "-1"
}

# TCP with both ports unknown could include port 3389.
could_be_rdp(protocol, _, _, _, true, true) := true if {
    protocol in {"tcp", "6", 6}
}

# Unknown starting port, known ending port.
could_be_rdp(protocol, _, to_port, _, true, false) := true if {
    protocol in {"tcp", "6", 6}
    is_number(to_port)
    to_port >= 3389
}

# Unknown ending port, known starting port.
could_be_rdp(protocol, from_port, _, _, false, true) := true if {
    protocol in {"tcp", "6", 6}
    is_number(from_port)
    from_port <= 3389
}

# Both ports known: determine whether the range includes 3389.
could_be_rdp(protocol, from_port, to_port, _, false, false) := true if {
    protocol in {"tcp", "6", 6}
    is_number(from_port)
    is_number(to_port)
    from_port <= 3389
    to_port >= 3389
}

# --------------------------------------------------
# Potentially public source helpers
# --------------------------------------------------

potentially_public_inline(rule, unknown_rule) := (
    true in [
        net002_contains_value(
            object.get(rule, "cidr_blocks", []),
            "0.0.0.0/0"
        ),
        net002_contains_value(
            object.get(rule, "ipv6_cidr_blocks", []),
            "::/0"
        ),
        net002_inline_cidr_unknown(unknown_rule, "cidr_blocks"),
        net002_inline_cidr_unknown(unknown_rule, "ipv6_cidr_blocks")
    ]
)

potentially_public_legacy(after, after_unknown) := (
    true in [
        net002_contains_value(
            object.get(after, "cidr_blocks", []),
            "0.0.0.0/0"
        ),
        net002_contains_value(
            object.get(after, "ipv6_cidr_blocks", []),
            "::/0"
        ),
        net002_has_unknown_collection_element(after_unknown, "cidr_blocks"),
        net002_has_unknown_collection_element(after_unknown, "ipv6_cidr_blocks")
    ]
)

potentially_public_modern(after, ipv4_unknown, ipv6_unknown) := (
    true in [
        object.get(after, "cidr_ipv4", null) == "0.0.0.0/0",
        object.get(after, "cidr_ipv6", null) == "::/0",
        ipv4_unknown,
        ipv6_unknown
    ]
)

# --------------------------------------------------
# Violation helpers
# --------------------------------------------------

known_rdp_violation(rc, family) := {
    "policy_id": "AWS-NET-002",
    "title": "Block Unrestricted RDP Ingress",
    "severity": "HIGH",
    "category": "NETWORK",
    "resource": rc.address,
    "message": sprintf(
        "RDP ingress on TCP port 3389 is unrestricted to the public internet over %s.",
        [family]
    ),
    "remediation": sprintf(
        "Restrict RDP ingress to approved trusted %s CIDR ranges, or remove the public ingress rule.",
        [family]
    )
}

unknown_rdp_violation(rc) := {
    "policy_id": "AWS-NET-002",
    "title": "Block Unrestricted RDP Ingress",
    "severity": "HIGH",
    "category": "NETWORK",
    "resource": rc.address,
    "message": "RDP ingress compliance cannot be determined because a security-relevant attribute is unknown during Terraform planning.",
    "remediation": "Resolve the unknown protocol, port, or CIDR values so the RDP ingress rule can be evaluated."
}

# --------------------------------------------------
# Inline rules: aws_security_group
# --------------------------------------------------

# Known-value IPv4 exposure.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_security_group"
    net002_is_active(rc)

    after := rc.change.after
    some rule in object.get(after, "ingress", [])

    allows_rdp(
        object.get(rule, "protocol", null),
        object.get(rule, "from_port", null),
        object.get(rule, "to_port", null)
    )

    net002_contains_value(
        object.get(rule, "cidr_blocks", []),
        "0.0.0.0/0"
    )

    violation := known_rdp_violation(rc, "IPv4")
}

# Known-value IPv6 exposure.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_security_group"
    net002_is_active(rc)

    after := rc.change.after
    some rule in object.get(after, "ingress", [])

    allows_rdp(
        object.get(rule, "protocol", null),
        object.get(rule, "from_port", null),
        object.get(rule, "to_port", null)
    )

    net002_contains_value(
        object.get(rule, "ipv6_cidr_blocks", []),
        "::/0"
    )

    violation := known_rdp_violation(rc, "IPv6")
}

# Unknown values: inline ingress rules.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_security_group"
    net002_is_active(rc)

    after := rc.change.after
    unknown := object.get(rc.change, "after_unknown", {})

    ingress := object.get(after, "ingress", [])
    unknown_ingress := object.get(unknown, "ingress", [])

    is_array(ingress)
    is_array(unknown_ingress)

    some i
    rule := ingress[i]
    unknown_rule := unknown_ingress[i]

    protocol_unknown := object.get(unknown_rule, "protocol", false) == true
    from_unknown := object.get(unknown_rule, "from_port", false) == true
    to_unknown := object.get(unknown_rule, "to_port", false) == true

    ipv4_unknown := net002_inline_cidr_unknown(unknown_rule, "cidr_blocks")
    ipv6_unknown := net002_inline_cidr_unknown(unknown_rule, "ipv6_cidr_blocks")

    net002_has_unknown_security_attribute(
        protocol_unknown,
        from_unknown,
        to_unknown,
        ipv4_unknown,
        ipv6_unknown
    )

    potentially_public_inline(rule, unknown_rule)

    could_be_rdp(
        object.get(rule, "protocol", null),
        object.get(rule, "from_port", null),
        object.get(rule, "to_port", null),
        protocol_unknown,
        from_unknown,
        to_unknown
    )

    violation := unknown_rdp_violation(rc)
}

# --------------------------------------------------
# Modern rules: aws_vpc_security_group_ingress_rule
# --------------------------------------------------

# Known-value IPv4 exposure.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_vpc_security_group_ingress_rule"
    net002_is_active(rc)

    after := rc.change.after

    allows_rdp(
        object.get(after, "ip_protocol", null),
        object.get(after, "from_port", null),
        object.get(after, "to_port", null)
    )

    object.get(after, "cidr_ipv4", null) == "0.0.0.0/0"

    violation := known_rdp_violation(rc, "IPv4")
}

# Known-value IPv6 exposure.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_vpc_security_group_ingress_rule"
    net002_is_active(rc)

    after := rc.change.after

    allows_rdp(
        object.get(after, "ip_protocol", null),
        object.get(after, "from_port", null),
        object.get(after, "to_port", null)
    )

    object.get(after, "cidr_ipv6", null) == "::/0"

    violation := known_rdp_violation(rc, "IPv6")
}

# Unknown values: modern ingress rules.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_vpc_security_group_ingress_rule"
    net002_is_active(rc)

    after := rc.change.after
    unknown := object.get(rc.change, "after_unknown", {})

    protocol_unknown := net002_is_unknown(unknown, "ip_protocol")
    from_unknown := net002_is_unknown(unknown, "from_port")
    to_unknown := net002_is_unknown(unknown, "to_port")

    ipv4_unknown := net002_is_unknown(unknown, "cidr_ipv4")
    ipv6_unknown := net002_is_unknown(unknown, "cidr_ipv6")

    net002_has_unknown_security_attribute(
        protocol_unknown,
        from_unknown,
        to_unknown,
        ipv4_unknown,
        ipv6_unknown
    )

    potentially_public_modern(after, ipv4_unknown, ipv6_unknown)

    could_be_rdp(
        object.get(after, "ip_protocol", null),
        object.get(after, "from_port", null),
        object.get(after, "to_port", null),
        protocol_unknown,
        from_unknown,
        to_unknown
    )

    violation := unknown_rdp_violation(rc)
}

# --------------------------------------------------
# Legacy rules: aws_security_group_rule
# --------------------------------------------------

# Known-value IPv4 exposure.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_security_group_rule"
    net002_is_active(rc)

    after := rc.change.after
    object.get(after, "type", null) == "ingress"

    allows_rdp(
        object.get(after, "protocol", null),
        object.get(after, "from_port", null),
        object.get(after, "to_port", null)
    )

    net002_contains_value(
        object.get(after, "cidr_blocks", []),
        "0.0.0.0/0"
    )

    violation := known_rdp_violation(rc, "IPv4")
}

# Known-value IPv6 exposure.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_security_group_rule"
    net002_is_active(rc)

    after := rc.change.after
    object.get(after, "type", null) == "ingress"

    allows_rdp(
        object.get(after, "protocol", null),
        object.get(after, "from_port", null),
        object.get(after, "to_port", null)
    )

    net002_contains_value(
        object.get(after, "ipv6_cidr_blocks", []),
        "::/0"
    )

    violation := known_rdp_violation(rc, "IPv6")
}

# Unknown values: legacy standalone ingress rules.
violations contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_security_group_rule"
    net002_is_active(rc)

    after := rc.change.after
    object.get(after, "type", null) == "ingress"

    unknown := object.get(rc.change, "after_unknown", {})

    protocol_unknown := net002_is_unknown(unknown, "protocol")
    from_unknown := net002_is_unknown(unknown, "from_port")
    to_unknown := net002_is_unknown(unknown, "to_port")

    ipv4_unknown := net002_has_unknown_collection_element(unknown, "cidr_blocks")
    ipv6_unknown := net002_has_unknown_collection_element(unknown, "ipv6_cidr_blocks")

    net002_has_unknown_security_attribute(
        protocol_unknown,
        from_unknown,
        to_unknown,
        ipv4_unknown,
        ipv6_unknown
    )

    potentially_public_legacy(after, unknown)

    could_be_rdp(
        object.get(after, "protocol", null),
        object.get(after, "from_port", null),
        object.get(after, "to_port", null),
        protocol_unknown,
        from_unknown,
        to_unknown
    )

    violation := unknown_rdp_violation(rc)
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
