############################################
# Provider
############################################
provider "aws" {
  region = "us-east-1"
}

############################################
# VPC
############################################
resource "aws_vpc" "dev_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "devsecops-vpc"
  }
}

############################################
# IAM ROLE + POLICY FOR VPC FLOW LOGS
############################################

# Role that VPC Flow Logs service will assume
resource "aws_iam_role" "flow_logs_role" {
  name = "devsecops-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Scoped IAM policy for CloudWatch Logs (NO Resource = "*")
resource "aws_iam_policy" "flow_logs_policy" {
  name = "devsecops-flow-logs-policy"

  # Use jsonencode so we can reference the log group ARN instead of "*"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        # Restrict resource to this project’s log group and its streams
        Resource = [
          aws_cloudwatch_log_group.vpc_logs.arn,
          "${aws_cloudwatch_log_group.vpc_logs.arn}:*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "flow_logs_attach" {
  role       = aws_iam_role.flow_logs_role.name
  policy_arn = aws_iam_policy.flow_logs_policy.arn
}

############################################
# KMS KEY FOR CLOUDWATCH LOG ENCRYPTION
############################################
resource "aws_kms_key" "cloudwatch_kms" {
  description         = "KMS key for encrypting VPC Flow Logs"
  enable_key_rotation = true

  # Simple secure key policy: root account + CloudWatch Logs service
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogsUse"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var_aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

# These data/locals help in the KMS policy (already Checkov-passing)
data "aws_caller_identity" "current" {}

locals {
  aws_region = "us-east-1"
}

############################################
# CLOUDWATCH LOG GROUP FOR VPC FLOW LOGS
############################################
resource "aws_cloudwatch_log_group" "vpc_logs" {
  name              = "/aws/vpc/devsecops-vpc-logs"
  retention_in_days = 400
  kms_key_id        = aws_kms_key.cloudwatch_kms.arn
}

############################################
# VPC FLOW LOGS
############################################
resource "aws_flow_log" "vpc_flow" {
  log_destination      = aws_cloudwatch_log_group.vpc_logs.arn
  log_destination_type = "cloud-watch-logs"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.dev_vpc.id
  iam_role_arn         = aws_iam_role.flow_logs_role.arn
}

############################################
# SUBNET
############################################
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.dev_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false

  tags = {
    Name = "devsecops-public-subnet"
  }
}

############################################
# DEFAULT SECURITY GROUP (LOCKED DOWN)
############################################
# This manages the *default* SG for the VPC and restricts all traffic
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.dev_vpc.id

  # No inbound or outbound allowed by default
  ingress = []
  egress  = []

  tags = {
    Name = "devsecops-default-sg-restricted"
  }
}

############################################
# APPLICATION SECURITY GROUP
############################################
resource "aws_security_group" "web_sg" {
  name        = "devsecops-web-sg"
  description = "Allow limited SSH and application traffic"
  vpc_id      = aws_vpc.dev_vpc.id

  # SSH only from your IP (replace YOUR_IP)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["YOUR_IP/32"] # TODO: replace with your real IP
    description = "SSH access from admin only"
  }

  # App traffic (Flask on 5000) from anywhere (demo)
  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "App traffic"
  }

  # OUTBOUND: Restrict to HTTP/HTTPS instead of -1 to 0.0.0.0/0
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP outbound"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound"
  }

  tags = {
    Name = "devsecops-web-sg"
  }
}

############################################
# IAM ROLE & INSTANCE PROFILE FOR EC2 (SSM)
############################################
resource "aws_iam_role" "ec2_role" {
  name = "devsecops-ec2-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "devsecops-ec2-instance-profile"
  role = aws_iam_role.ec2_role.name
}

############################################
# EC2 INSTANCE
############################################
resource "aws_instance" "app_server" {
  ami                    = "ami-0c55b159cbfafe1f0" # Example AMI (Ubuntu)
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  # Enable detailed monitoring & EBS optimization
  monitoring    = true
  ebs_optimized = true

  # Instance Metadata Service v2 only
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  # Encrypted root EBS volume
  root_block_device {
    volume_type = "gp3"
    volume_size = 8
    encrypted   = true
  }

  tags = {
    Name = "devsecops-app-server"
  }

  # Basic provisioning (you could later add Ansible or userdata for Docker app)
  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y docker.io python3 python3-pip
              mkdir -p /opt/app/src
              EOF
}
