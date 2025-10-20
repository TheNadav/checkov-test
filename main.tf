terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-vulnerable-test-bucket-${random_id.bucket_id.hex}"
}

resource "random_id" "bucket_id" {
  byte_length = 8
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bad_encryption" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "bad_public_access" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_instance" "vulnerable_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  metadata_options {
    http_tokens = "optional"
  }

  associate_public_ip_address = true

  monitoring = false

  tags = {
    Name = "VulnerableInstance"
  }
}

resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-sg"
  description = "Intentionally insecure security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH from anywhere"
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "vulnerable_db" {
  identifier           = "vulnerable-database"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "hardcodedpassword123"
  skip_final_snapshot  = true

  storage_encrypted = false

  publicly_accessible = true

  backup_retention_period = 0

  deletion_protection = false

  multi_az = false
}

resource "aws_iam_role" "vulnerable_role" {
  name = "vulnerable-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "vulnerable_policy" {
  name = "vulnerable-policy"
  role = aws_iam_role.vulnerable_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "*"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_ebs_volume" "vulnerable_volume" {
  availability_zone = "us-east-1a"
  size              = 10

  encrypted = false

  tags = {
    Name = "VulnerableVolume"
  }
}

resource "aws_cloudtrail" "vulnerable_trail" {
  name                          = "vulnerable-trail"
  s3_bucket_name                = aws_s3_bucket.vulnerable_bucket.id
  include_global_service_events = false

  enable_log_file_validation = false

  is_multi_region_trail = false
}

resource "aws_lambda_function" "vulnerable_lambda" {
  filename      = "lambda.zip"
  function_name = "vulnerable-function"
  role          = aws_iam_role.vulnerable_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  environment {
    variables = {
      DB_PASSWORD = "supersecret123"
      API_KEY     = "sk-1234567890abcdef"
    }
  }

  tracing_config {
    mode = "PassThrough"
  }
}

resource "aws_elasticsearch_domain" "vulnerable_es" {
  domain_name           = "vulnerable-elasticsearch"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t3.small.elasticsearch"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  encrypt_at_rest {
    enabled = false
  }

  node_to_node_encryption {
    enabled = false
  }

  domain_endpoint_options {
    enforce_https = false
  }
}

resource "aws_redshift_cluster" "vulnerable_redshift" {
  cluster_identifier = "vulnerable-redshift"
  database_name      = "mydb"
  master_username    = "admin"
  master_password    = "Password123"
  node_type          = "dc2.large"
  cluster_type       = "single-node"

  encrypted                  = false
  publicly_accessible        = true
  skip_final_snapshot        = true
  automated_snapshot_retention_period = 0

  logging {
    enable = false
  }
}

resource "aws_eks_cluster" "vulnerable_eks" {
  name     = "vulnerable-cluster"
  role_arn = aws_iam_role.vulnerable_role.arn

  vpc_config {
    endpoint_private_access = false
    endpoint_public_access  = true
    public_access_cidrs     = ["0.0.0.0/0"]
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = ""
    }
  }

  enabled_cluster_log_types = []
}

resource "aws_kms_key" "vulnerable_kms" {
  description             = "Vulnerable KMS key"
  deletion_window_in_days = 7
  enable_key_rotation     = false
}

resource "aws_dynamodb_table" "vulnerable_dynamodb" {
  name           = "vulnerable-table"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }

  server_side_encryption {
    enabled = false
  }
}

resource "aws_efs_file_system" "vulnerable_efs" {
  creation_token = "vulnerable-efs"
  encrypted      = false
}

resource "aws_api_gateway_rest_api" "vulnerable_api" {
  name        = "vulnerable-api"
  description = "Vulnerable API Gateway"
}

resource "aws_api_gateway_method" "vulnerable_method" {
  rest_api_id   = aws_api_gateway_rest_api.vulnerable_api.id
  resource_id   = aws_api_gateway_rest_api.vulnerable_api.root_resource_id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_sns_topic" "vulnerable_sns" {
  name = "vulnerable-topic"
}

resource "aws_sqs_queue" "vulnerable_sqs" {
  name = "vulnerable-queue"
}

resource "aws_ecr_repository" "vulnerable_ecr" {
  name                 = "vulnerable-repo"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}

resource "aws_elb" "vulnerable_elb" {
  name               = "vulnerable-elb"
  availability_zones = ["us-east-1a", "us-east-1b"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    target              = "HTTP:80/"
    interval            = 30
  }

  cross_zone_load_balancing   = false
  idle_timeout                = 400
  connection_draining         = false
}

resource "aws_network_acl" "vulnerable_nacl" {
  vpc_id = aws_vpc.vulnerable_vpc.id

  ingress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}

resource "aws_vpc" "vulnerable_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "vulnerable_subnet" {
  vpc_id                  = aws_vpc.vulnerable_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}

resource "aws_secretsmanager_secret" "vulnerable_secret" {
  name = "vulnerable-secret"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "vulnerable_secret_value" {
  secret_id     = aws_secretsmanager_secret.vulnerable_secret.id
  secret_string = jsonencode({
    password = "hardcoded-password-in-code"
    api_key  = "1234567890"
  })
}
