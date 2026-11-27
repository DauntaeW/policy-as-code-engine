
package main

import rego.v1

# AWS-NET-003
# Block unrestricted public database ingress.
#
# Supported resources:
# - aws_security_group (inline ingress)
# - aws_security_group_rule (legacy standalone ingress)
# - aws_vpc_security_group_ingress_rule (modern standalone ingress)

net003_database_ports := {
	1433: "Microsoft SQL Server",
	3306: "MySQL",
	5432: "PostgreSQL",
}

# ------------------------------------------------------------
# 1. Terraform action eligibility
# ------------------------------------------------------------

net003_eligible(resource_change) if {
	some action in resource_change.change.actions
	action in {"create", "update"}
}

# ------------------------------------------------------------
# 2. Protocol normalization
# ------------------------------------------------------------

net003_is_tcp(protocol) if {
    protocol == "tcp"
}

net003_is_tcp(protocol) if {
    protocol == "6"
}

net003_is_tcp(protocol) if {
    protocol == 6
}

net003_is_all_protocols(protocol) if {
    protocol == "-1"
}

net003_is_all_protocols(protocol) if {
    protocol == -1
}

net003_is_database_protocol(protocol) if {
    net003_is_tcp(protocol)
}

net003_is_database_protocol(protocol) if {
    net003_is_all_protocols(protocol)
}

# ------------------------------------------------------------
# 3. Port-range evaluation
# ------------------------------------------------------------

net003_matches_database_port(rule, port) if {
	is_number(rule.from_port)
	is_number(rule.to_port)
	rule.from_port <= port
	port <= rule.to_port
}

# ------------------------------------------------------------
# 4. Public CIDR detection
# ------------------------------------------------------------

net003_has_public_ipv4(rule) if {
	is_array(object.get(rule, "cidr_blocks", null))
	some cidr in rule.cidr_blocks
	cidr == "0.0.0.0/0"
}

net003_has_public_ipv4(rule) if {
	object.get(rule, "cidr_ipv4", null) == "0.0.0.0/0"
}

net003_has_public_ipv6(rule) if {
	is_array(object.get(rule, "ipv6_cidr_blocks", null))
	some cidr in rule.ipv6_cidr_blocks
	cidr == "::/0"
}

net003_has_public_ipv6(rule) if {
	object.get(rule, "cidr_ipv6", null) == "::/0"
}

net003_has_public_source(rule) if {
	net003_has_public_ipv4(rule)
}

net003_has_public_source(rule) if {
	net003_has_public_ipv6(rule)
}

# ------------------------------------------------------------
# 5. Unknown-value detection
# ------------------------------------------------------------

# Terraform after_unknown can represent an unknown field
# as true or as an array containing unknown elements.

net003_any_unknown(value) if {
	value == true
}

net003_any_unknown(value) if {
	is_array(value)
	some item in value
	item == true
}

net003_field_unknown(unknown, field) if {
	net003_any_unknown(
		object.get(unknown, field, false)
	)
}

net003_protocol_unknown(unknown) if {
	net003_field_unknown(unknown, "protocol")
}

net003_protocol_unknown(unknown) if {
	net003_field_unknown(unknown, "ip_protocol")
}

net003_port_unknown(unknown) if {
	net003_field_unknown(unknown, "from_port")
}

net003_port_unknown(unknown) if {
	net003_field_unknown(unknown, "to_port")
}

net003_cidr_unknown(unknown) if {
	net003_field_unknown(unknown, "cidr_blocks")
}

net003_cidr_unknown(unknown) if {
	net003_field_unknown(unknown, "ipv6_cidr_blocks")
}

net003_cidr_unknown(unknown) if {
	net003_field_unknown(unknown, "cidr_ipv4")
}

net003_cidr_unknown(unknown) if {
	net003_field_unknown(unknown, "cidr_ipv6")
}

# ------------------------------------------------------------
# 6. Determine whether a rule could expose a database port
# ------------------------------------------------------------

net003_protocol_possible(rule, unknown) if {
    net003_is_database_protocol(rule.protocol)
}

net003_protocol_possible(rule, unknown) if {
    net003_is_database_protocol(rule.ip_protocol)
}

net003_protocol_possible(rule, unknown) if {
    net003_protocol_unknown(unknown)
}

net003_port_possible(rule, unknown, port) if {
    net003_matches_database_port(rule, port)
}

net003_port_possible(_, unknown, _) if {
    net003_field_unknown(unknown, "from_port")
    net003_field_unknown(unknown, "to_port")
}

net003_port_possible(rule, unknown, port) if {
    net003_field_unknown(unknown, "from_port")
    not net003_field_unknown(unknown, "to_port")
    is_number(rule.to_port)
    port <= rule.to_port
}

net003_port_possible(rule, unknown, port) if {
    not net003_field_unknown(unknown, "from_port")
    net003_field_unknown(unknown, "to_port")
    is_number(rule.from_port)
    rule.from_port <= port
}

net003_source_possible(rule, unknown) if {
	net003_has_public_source(rule)
}

net003_source_possible(rule, unknown) if {
	net003_cidr_unknown(unknown)
}

# ------------------------------------------------------------
# 7. Confirmed exposure detection
# ------------------------------------------------------------

net003_confirmed_exposure(rule, port) if {
    net003_is_tcp(rule.protocol)
    net003_matches_database_port(rule, port)
    net003_has_public_source(rule)
}

net003_confirmed_exposure(rule, port) if {
    net003_is_tcp(rule.ip_protocol)
    net003_matches_database_port(rule, port)
    net003_has_public_source(rule)
}

net003_confirmed_exposure(rule, port) if {
    net003_is_all_protocols(rule.protocol)
    net003_has_public_source(rule)
}

net003_confirmed_exposure(rule, port) if {
    net003_is_all_protocols(rule.ip_protocol)
    net003_has_public_source(rule)
}

# ------------------------------------------------------------
# 8. Indeterminate exposure detection
# ------------------------------------------------------------

net003_indeterminate_exposure(rule, unknown, port) if {
	net003_protocol_possible(rule, unknown)
	net003_port_possible(rule, unknown, port)
	net003_source_possible(rule, unknown)

	not net003_confirmed_exposure(rule, port)
}

# ------------------------------------------------------------
# 9. Canonical violation objects
# ------------------------------------------------------------

net003_violation(resource, port) := {
	"policy_id": "AWS-NET-003",
	"title": "Block unrestricted public database ingress",
	"severity": "HIGH",
	"category": "NETWORK",
	"resource": resource,
	"message": sprintf(
		"Public %s ingress detected on TCP port %d from an unrestricted IPv4 or IPv6 source.",
		[net003_database_ports[port], port],
	),
	"remediation": "Restrict database ingress to explicitly approved private CIDR ranges or trusted security-group sources.",
}

net003_unknown_violation(resource, port) := {
	"policy_id": "AWS-NET-003",
	"title": "Block unrestricted public database ingress",
	"severity": "HIGH",
	"category": "NETWORK",
	"resource": resource,
	"message": sprintf(
		"Unable to verify whether ingress exposes %s on TCP port %d because relevant Terraform values are unknown. Policy enforcement is blocked until these values are known.",
		[net003_database_ports[port], port],
	),
	"remediation": "Resolve unknown protocol, port-range, and source CIDR values before applying the Terraform plan. Ensure database ingress is restricted to explicitly approved sources.",
}

net003_index_or_default(array, index, fallback) := value if {
	is_array(array)
	count(array) > index
	value := array[index]
} else := fallback

# ------------------------------------------------------------
# 10. Inline security-group ingress
# ------------------------------------------------------------

violations contains violation if {
	some resource_change in input.resource_changes
	net003_eligible(resource_change)
	resource_change.type == "aws_security_group"

	after := resource_change.change.after
	is_object(after)

	rules := object.get(after, "ingress", [])
	is_array(rules)

	after_unknown := object.get(
		resource_change.change,
		"after_unknown",
		{},
	)

	unknown_rules := object.get(
		after_unknown,
		"ingress",
		[],
	)

	some index, rule in rules

	rule_unknown := net003_index_or_default(
		unknown_rules,
		index,
		{},
	)

	some port, _ in net003_database_ports

	net003_confirmed_exposure(rule, port)

	resource := sprintf(
		"%s.ingress[%d]",
		[resource_change.address, index],
	)

	violation := net003_violation(resource, port)
}

violations contains violation if {
	some resource_change in input.resource_changes
	net003_eligible(resource_change)
	resource_change.type == "aws_security_group"

	after := resource_change.change.after
	is_object(after)

	rules := object.get(after, "ingress", [])
	is_array(rules)

	after_unknown := object.get(
		resource_change.change,
		"after_unknown",
		{},
	)

	unknown_rules := object.get(
		after_unknown,
		"ingress",
		[],
	)

	some index, rule in rules

	rule_unknown := net003_index_or_default(
		unknown_rules,
		index,
		{},
	)

	some port, _ in net003_database_ports

	net003_indeterminate_exposure(
		rule,
		rule_unknown,
		port,
	)

	resource := sprintf(
		"%s.ingress[%d]",
		[resource_change.address, index],
	)

	violation := net003_unknown_violation(resource, port)
}

# ------------------------------------------------------------
# 11. Legacy standalone security-group ingress rules
# ------------------------------------------------------------

violations contains violation if {
	some resource_change in input.resource_changes
	net003_eligible(resource_change)
	resource_change.type == "aws_security_group_rule"

	after := resource_change.change.after
	is_object(after)
	after.type == "ingress"

	some port, _ in net003_database_ports

	net003_confirmed_exposure(after, port)

	violation := net003_violation(
		resource_change.address,
		port,
	)
}

violations contains violation if {
	some resource_change in input.resource_changes
	net003_eligible(resource_change)
	resource_change.type == "aws_security_group_rule"

	after := resource_change.change.after
	is_object(after)
	after.type == "ingress"

	unknown := object.get(
		resource_change.change,
		"after_unknown",
		{},
	)

	some port, _ in net003_database_ports

	net003_indeterminate_exposure(
		after,
		unknown,
		port,
	)

	violation := net003_unknown_violation(
		resource_change.address,
		port,
	)
}

# ------------------------------------------------------------
# 12. Modern standalone security-group ingress rules
# ------------------------------------------------------------

violations contains violation if {
	some resource_change in input.resource_changes
	net003_eligible(resource_change)
	resource_change.type == "aws_vpc_security_group_ingress_rule"

	after := resource_change.change.after
	is_object(after)

	some port, _ in net003_database_ports

	net003_confirmed_exposure(after, port)

	violation := net003_violation(
		resource_change.address,
		port,
	)
}

violations contains violation if {
	some resource_change in input.resource_changes
	net003_eligible(resource_change)
	resource_change.type == "aws_vpc_security_group_ingress_rule"

	after := resource_change.change.after
	is_object(after)

	unknown := object.get(
		resource_change.change,
		"after_unknown",
		{},
	)

	some port, _ in net003_database_ports

	net003_indeterminate_exposure(
		after,
		unknown,
		port,
	)

	violation := net003_unknown_violation(
		resource_change.address,
		port,
	)
}

# ------------------------------------------------------------
# 13. Conftest compatibility adapter
# ------------------------------------------------------------

deny contains result if {
	some violation in violations

	result := object.union(
		violation,
		{"msg": violation.message},
	)
}
