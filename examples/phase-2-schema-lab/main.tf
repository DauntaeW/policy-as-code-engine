
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
    description      = "Restricted RDP IPv4 and IPv6"
    from_port        = 3389
    to_port          = 3389
    protocol         = "tcp"
    cidr_blocks      = ["203.0.113.10/32"]
    ipv6_cidr_blocks = ["2001:db8::10/128"]
  }

  # NET-003 database schema probes

  ingress {
    description      = "PostgreSQL 5432 - schema probe"
    from_port        = 5432
    to_port          = 5432
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description      = "MySQL 3306 - schema probe"
    from_port        = 3306
    to_port          = 3306
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description      = "SQL Server 1433 - schema probe"
    from_port        = 1433
    to_port          = 1433
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
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
  description       = "Restricted RDP IPv4"
  ip_protocol       = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_ipv4         = "203.0.113.10/32"
}

resource "aws_vpc_security_group_ingress_rule" "modern_rdp_ipv6" {
  security_group_id = aws_security_group.modern.id
  description       = "Restricted RDP IPv6"
  ip_protocol       = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_ipv6         = "2001:db8::10/128"
}

# NET-003 database schema probes - modern resources

# PostgreSQL
resource "aws_vpc_security_group_ingress_rule" "modern_postgres_ipv4" {
  security_group_id = aws_security_group.modern.id
  description       = "PostgreSQL 5432 schema probe IPv4"
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "modern_postgres_ipv6" {
  security_group_id = aws_security_group.modern.id
  description       = "PostgreSQL 5432 schema probe IPv6"
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
  cidr_ipv6         = "::/0"
}

# MySQL
resource "aws_vpc_security_group_ingress_rule" "modern_mysql_ipv4" {
  security_group_id = aws_security_group.modern.id
  description       = "MySQL 3306 schema probe IPv4"
  ip_protocol       = "tcp"
  from_port         = 3306
  to_port           = 3306
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "modern_mysql_ipv6" {
  security_group_id = aws_security_group.modern.id
  description       = "MySQL 3306 schema probe IPv6"
  ip_protocol       = "tcp"
  from_port         = 3306
  to_port           = 3306
  cidr_ipv6         = "::/0"
}

# SQL Server
resource "aws_vpc_security_group_ingress_rule" "modern_sqlserver_ipv4" {
  security_group_id = aws_security_group.modern.id
  description       = "SQL Server 1433 schema probe IPv4"
  ip_protocol       = "tcp"
  from_port         = 1433
  to_port           = 1433
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "modern_sqlserver_ipv6" {
  security_group_id = aws_security_group.modern.id
  description       = "SQL Server 1433 schema probe IPv6"
  ip_protocol       = "tcp"
  from_port         = 1433
  to_port           = 1433
  cidr_ipv6         = "::/0"
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
  description       = "Restricted RDP IPv4"
  protocol          = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_blocks       = ["203.0.113.10/32"]
}

resource "aws_security_group_rule" "legacy_rdp_ipv6" {
  type              = "ingress"
  security_group_id = aws_security_group.legacy.id
  description       = "Restricted RDP IPv6"
  protocol          = "tcp"
  from_port         = 3389
  to_port           = 3389
  ipv6_cidr_blocks  = ["2001:db8::10/128"]
}

# NET-003 database schema probes - legacy resources

# PostgreSQL
resource "aws_security_group_rule" "legacy_postgres_ipv4" {
  type              = "ingress"
  security_group_id = aws_security_group.legacy.id
  description       = "PostgreSQL 5432 schema probe IPv4"
  protocol          = "tcp"
  from_port         = 5432
  to_port           = 5432
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "legacy_postgres_ipv6" {
  type              = "ingress"
  security_group_id = aws_security_group.legacy.id
  description       = "PostgreSQL 5432 schema probe IPv6"
  protocol          = "tcp"
  from_port         = 5432
  to_port           = 5432
  ipv6_cidr_blocks  = ["::/0"]
}

# MySQL
resource "aws_security_group_rule" "legacy_mysql_ipv4" {
  type              = "ingress"
  security_group_id = aws_security_group.legacy.id
  description       = "MySQL 3306 schema probe IPv4"
  protocol          = "tcp"
  from_port         = 3306
  to_port           = 3306
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "legacy_mysql_ipv6" {
  type              = "ingress"
  security_group_id = aws_security_group.legacy.id
  description       = "MySQL 3306 schema probe IPv6"
  protocol          = "tcp"
  from_port         = 3306
  to_port           = 3306
  ipv6_cidr_blocks  = ["::/0"]
}

# SQL Server
resource "aws_security_group_rule" "legacy_sqlserver_ipv4" {
  type              = "ingress"
  security_group_id = aws_security_group.legacy.id
  description       = "SQL Server 1433 schema probe IPv4"
  protocol          = "tcp"
  from_port         = 1433
  to_port           = 1433
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "legacy_sqlserver_ipv6" {
  type              = "ingress"
  security_group_id = aws_security_group.legacy.id
  description       = "SQL Server 1433 schema probe IPv6"
  protocol          = "tcp"
  from_port         = 1433
  to_port           = 1433
  ipv6_cidr_blocks  = ["::/0"]
}
