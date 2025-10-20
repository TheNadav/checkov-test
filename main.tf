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

resource "aws_alb" "vulnerable_alb" {
  name               = "vulnerable-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = [aws_subnet.vulnerable_subnet.id, aws_subnet.vulnerable_subnet2.id]

  enable_deletion_protection = false
  enable_http2              = true
  drop_invalid_header_fields = false

  access_logs {
    enabled = false
    bucket  = aws_s3_bucket.vulnerable_bucket.bucket
  }
}

resource "aws_subnet" "vulnerable_subnet2" {
  vpc_id                  = aws_vpc.vulnerable_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true
}

resource "aws_alb_listener" "vulnerable_listener" {
  load_balancer_arn = aws_alb.vulnerable_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "forward"
    target_group_arn = aws_alb_target_group.vulnerable_tg.arn
  }
}

resource "aws_alb_target_group" "vulnerable_tg" {
  name     = "vulnerable-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.vulnerable_vpc.id
}

resource "aws_docdb_cluster" "vulnerable_docdb" {
  cluster_identifier      = "vulnerable-docdb"
  engine                  = "docdb"
  master_username         = "admin"
  master_password         = "mustbeeightcharacters"
  backup_retention_period = 1
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true

  storage_encrypted = false
  enabled_cloudwatch_logs_exports = []
}

resource "aws_neptune_cluster" "vulnerable_neptune" {
  cluster_identifier                  = "vulnerable-neptune"
  engine                              = "neptune"
  backup_retention_period             = 1
  preferred_backup_window             = "07:00-09:00"
  skip_final_snapshot                 = true
  iam_database_authentication_enabled = false
  storage_encrypted                   = false
  enable_cloudwatch_logs_exports      = []
}

resource "aws_mq_broker" "vulnerable_mq" {
  broker_name = "vulnerable-broker"

  engine_type        = "ActiveMQ"
  engine_version     = "5.15.0"
  host_instance_type = "mq.t2.micro"

  user {
    username = "admin"
    password = "AdminPassword123"
  }

  publicly_accessible = true
  encryption_options {
    use_aws_owned_key = true
  }

  logs {
    general = false
    audit   = false
  }
}

resource "aws_elasticache_cluster" "vulnerable_elasticache" {
  cluster_id           = "vulnerable-cluster"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  engine_version       = "7.0"
  port                 = 6379

  snapshot_retention_limit = 0
  transit_encryption_enabled = false
}

resource "aws_kinesis_stream" "vulnerable_kinesis" {
  name             = "vulnerable-stream"
  shard_count      = 1
  retention_period = 24

  encryption_type = "NONE"
}

resource "aws_sagemaker_notebook_instance" "vulnerable_sagemaker" {
  name          = "vulnerable-notebook"
  role_arn      = aws_iam_role.vulnerable_role.arn
  instance_type = "ml.t2.medium"

  direct_internet_access = "Enabled"
  root_access           = "Enabled"
}

resource "aws_dax_cluster" "vulnerable_dax" {
  cluster_name       = "vulnerable-dax-cluster"
  iam_role_arn       = aws_iam_role.vulnerable_role.arn
  node_type          = "dax.t3.small"
  replication_factor = 1

  server_side_encryption {
    enabled = false
  }
}

resource "aws_msk_cluster" "vulnerable_msk" {
  cluster_name           = "vulnerable-msk"
  kafka_version          = "2.8.0"
  number_of_broker_nodes = 2

  broker_node_group_info {
    instance_type   = "kafka.t3.small"
    client_subnets  = [aws_subnet.vulnerable_subnet.id, aws_subnet.vulnerable_subnet2.id]
    security_groups = [aws_security_group.vulnerable_sg.id]

    storage_info {
      ebs_storage_info {
        volume_size = 100
      }
    }
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "PLAINTEXT"
      in_cluster    = false
    }
    encryption_at_rest_kms_key_arn = ""
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled = false
      }
      firehose {
        enabled = false
      }
      s3 {
        enabled = false
      }
    }
  }
}

resource "aws_qldb_ledger" "vulnerable_qldb" {
  name             = "vulnerable-ledger"
  permissions_mode = "ALLOW_ALL"
  deletion_protection = false
}

resource "aws_glue_data_catalog_encryption_settings" "vulnerable_glue" {
  data_catalog_encryption_settings {
    connection_password_encryption {
      return_connection_password_encrypted = false
    }

    encryption_at_rest {
      catalog_encryption_mode = "DISABLED"
    }
  }
}

resource "aws_athena_workgroup" "vulnerable_athena" {
  name = "vulnerable-workgroup"

  configuration {
    enforce_workgroup_configuration    = false
    publish_cloudwatch_metrics_enabled = false

    result_configuration {
      output_location = "s3://${aws_s3_bucket.vulnerable_bucket.bucket}/output/"
    }
  }
}

resource "aws_backup_vault" "vulnerable_backup" {
  name = "vulnerable_backup_vault"
}

resource "aws_cloudfront_distribution" "vulnerable_cloudfront" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.vulnerable_bucket.bucket_regional_domain_name
    origin_id   = "vulnerable-origin"
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "vulnerable-origin"
    viewer_protocol_policy = "allow-all"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  logging_config {
    include_cookies = false
    bucket          = ""
    prefix          = ""
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}

resource "aws_codebuild_project" "vulnerable_codebuild" {
  name          = "vulnerable-project"
  service_role  = aws_iam_role.vulnerable_role.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = true

    environment_variable {
      name  = "API_KEY"
      value = "hardcoded-api-key-12345"
      type  = "PLAINTEXT"
    }
  }

  source {
    type = "NO_SOURCE"
    buildspec = "version: 0.2"
  }

  logs_config {
    cloudwatch_logs {
      status = "DISABLED"
    }
    s3_logs {
      status = "DISABLED"
    }
  }
}

resource "aws_workspaces_workspace" "vulnerable_workspace" {
  directory_id = "d-12345"
  bundle_id    = "wsb-12345"
  user_name    = "admin"

  root_volume_encryption_enabled = false
  user_volume_encryption_enabled = false
  volume_encryption_key          = ""

  workspace_properties {
    user_volume_size_gib = 10
    root_volume_size_gib = 80
  }
}

resource "aws_guardduty_detector" "vulnerable_guardduty" {
  enable = true

  datasources {
    s3_logs {
      enable = false
    }
    kubernetes {
      audit_logs {
        enable = false
      }
    }
  }
}

resource "aws_config_configuration_recorder" "vulnerable_config" {
  name     = "vulnerable-recorder"
  role_arn = aws_iam_role.vulnerable_role.arn

  recording_group {
    all_supported = false
  }
}

resource "aws_wafv2_web_acl" "vulnerable_waf" {
  name  = "vulnerable-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "vulnerable-waf"
    sampled_requests_enabled   = false
  }
}

resource "aws_transfer_server" "vulnerable_transfer" {
  endpoint_type = "PUBLIC"

  protocols   = ["FTP"]
  identity_provider_type = "SERVICE_MANAGED"
}

resource "aws_batch_compute_environment" "vulnerable_batch" {
  name = "vulnerable-batch"
  type                     = "MANAGED"

  compute_resources {
    type = "EC2"
    allocation_strategy = "BEST_FIT_PROGRESSIVE"
    instance_role = aws_iam_role.vulnerable_role.arn
    instance_type = ["optimal"]
    max_vcpus = 16
    min_vcpus = 0
    security_group_ids = [aws_security_group.vulnerable_sg.id]
    subnets = [aws_subnet.vulnerable_subnet.id]
  }

  service_role = aws_iam_role.vulnerable_role.arn
}

resource "aws_iam_user" "vulnerable_user" {
  name = "vulnerable-user"
}

resource "aws_iam_access_key" "vulnerable_access_key" {
  user = aws_iam_user.vulnerable_user.name
}

resource "aws_iam_user_policy_attachment" "vulnerable_user_policy" {
  user       = aws_iam_user.vulnerable_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
