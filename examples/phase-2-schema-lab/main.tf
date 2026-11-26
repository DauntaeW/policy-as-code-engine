
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.73.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "testing"
  secret_key                  = "testing"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

# 1. Inline ingress rules
resource "aws_security_group" "inline" {
  name        = "schema-lab-inline"
  description = "Schema inspection only"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress {
    description      = "Restricted SSH IPv4 and IPv6"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["203.0.113.10/32"]
    ipv6_cidr_blocks = ["2001:db8::10/128"]
  }

  ingress {
    description      = "Unrestricted RDP IPv4 and IPv6 - intentional policy violations"
    from_port        = 3389
    to_port          = 3389
    protocol         = "tcp"
    cidr_blocks      = ["203.0.113.10/32"]
    ipv6_cidr_blocks = ["2001:db8::10/128"]
  }
}

# 2. Modern standalone ingress rules
resource "aws_security_group" "modern" {
  name        = "schema-lab-modern"
  description = "Schema inspection only"
  vpc_id      = "vpc-0123456789abcdef0"
}

resource "aws_vpc_security_group_ingress_rule" "modern_ipv4" {
  security_group_id = aws_security_group.modern.id
  description       = "Restricted SSH IPv4"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "203.0.113.10/32"
}

resource "aws_vpc_security_group_ingress_rule" "modern_ipv6" {
  security_group_id = aws_security_group.modern.id
  description       = "Restricted SSH IPv6"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv6         = "2001:db8::10/128"
}

resource "aws_vpc_security_group_ingress_rule" "modern_rdp_ipv4" {
  security_group_id = aws_security_group.modern.id
  description       = "Unrestricted RDP IPv4 - intentional policy violation"
  ip_protocol       = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_ipv4         = "203.0.113.10/32"
}

resource "aws_vpc_security_group_ingress_rule" "modern_rdp_ipv6" {
  security_group_id = aws_security_group.modern.id
  description       = "Unrestricted RDP IPv6 - intentional policy violation"
  ip_protocol       = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_ipv6         = "2001:db8::10/128"
}

# 3. Legacy standalone ingress rules
resource "aws_security_group" "legacy" {
  name        = "schema-lab-legacy"
  description = "Schema inspection only"
  vpc_id      = "vpc-0123456789abcdef0"
}

resource "aws_security_group_rule" "legacy_ipv4" {
  type              = "ingress"
  security_group_id = aws_security_group.legacy.id
  description       = "Restricted SSH IPv4"
  protocol          = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_blocks       = ["203.0.113.10/32"]
}

resource "aws_security_group_rule" "legacy_ipv6" {
  type              = "ingress"
  security_group_id = aws_security_group.legacy.id
  description       = "Restricted SSH IPv6"
  protocol          = "tcp"
  from_port         = 22
  to_port           = 22
  ipv6_cidr_blocks  = ["2001:db8::10/128"]
}

resource "aws_security_group_rule" "legacy_rdp_ipv4" {
  type              = "ingress"
  security_group_id = aws_security_group.legacy.id
  description       = "Unrestricted RDP IPv4 - intentional policy violation"
  protocol          = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_blocks       = ["203.0.113.10/32"]
}

resource "aws_security_group_rule" "legacy_rdp_ipv6" {
  type              = "ingress"
  security_group_id = aws_security_group.legacy.id
  description       = "Unrestricted RDP IPv6 - intentional policy violation"
  protocol          = "tcp"
  from_port         = 3389
  to_port           = 3389
  ipv6_cidr_blocks  = ["2001:db8::10/128"]
}
