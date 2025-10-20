resource "aws_s3_bucket" "critical_public_bucket" {
  bucket = "critical-public-bucket-${random_id.bucket_id.hex}"
}

resource "aws_s3_bucket_policy" "allow_public_access" {
  bucket = aws_s3_bucket.critical_public_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "${aws_s3_bucket.critical_public_bucket.arn}",
          "${aws_s3_bucket.critical_public_bucket.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_policy" "admin_policy" {
  name        = "admin-policy"
  description = "Policy with admin access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "admin_attach" {
  user       = aws_iam_user.vulnerable_user.name
  policy_arn = aws_iam_policy.admin_policy.arn
}

resource "aws_db_instance" "public_db" {
  identifier           = "public-database"
  engine               = "postgres"
  engine_version       = "13.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  skip_final_snapshot  = true
  publicly_accessible  = true
  storage_encrypted    = false

  vpc_security_group_ids = [aws_security_group.vulnerable_sg.id]
}

resource "aws_instance" "unencrypted_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  root_block_device {
    encrypted = false
  }

  metadata_options {
    http_tokens = "optional"
    http_endpoint = "enabled"
  }

  user_data = <<-EOF
              #!/bin/bash
              export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
              export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
              export DB_PASSWORD=SuperSecret123
              EOF

  associate_public_ip_address = true
}

resource "aws_security_group" "completely_open" {
  name        = "completely-open"
  description = "No restrictions"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "unencrypted_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

resource "aws_rds_cluster" "public_cluster" {
  cluster_identifier      = "public-aurora-cluster"
  engine                  = "aurora-mysql"
  engine_version          = "5.7.mysql_aurora.2.10.1"
  master_username         = "admin"
  master_password         = "password"
  skip_final_snapshot     = true
  storage_encrypted       = false

  vpc_security_group_ids = [aws_security_group.completely_open.id]
}

resource "aws_elasticache_replication_group" "public_redis" {
  replication_group_id       = "public-redis"
  description               = "Public Redis cluster"
  node_type                  = "cache.t3.micro"
  num_cache_clusters         = 2
  port                       = 6379

  at_rest_encryption_enabled = false
  transit_encryption_enabled = false

  security_group_ids = [aws_security_group.completely_open.id]
}

resource "aws_efs_file_system" "public_efs" {
  creation_token = "public-efs"
  encrypted      = false
}

resource "aws_efs_mount_target" "public_mount" {
  file_system_id  = aws_efs_file_system.public_efs.id
  subnet_id       = aws_subnet.vulnerable_subnet.id
  security_groups = [aws_security_group.completely_open.id]
}

resource "aws_ecr_repository" "public_repo" {
  name                 = "public-repo"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}

resource "aws_ecr_repository_policy" "public_policy" {
  repository = aws_ecr_repository.public_repo.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPull"
        Effect = "Allow"
        Principal = "*"
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
      }
    ]
  })
}

resource "aws_elasticsearch_domain" "public_es" {
  domain_name           = "public-elasticsearch"
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

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action   = "es:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_sns_topic" "public_topic" {
  name = "public-topic"
}

resource "aws_sns_topic_policy" "public_sns_policy" {
  arn = aws_sns_topic.public_topic.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action   = "SNS:*"
        Resource = aws_sns_topic.public_topic.arn
      }
    ]
  })
}

resource "aws_sqs_queue" "public_queue" {
  name = "public-queue"
}

resource "aws_sqs_queue_policy" "public_sqs_policy" {
  queue_url = aws_sqs_queue.public_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action   = "sqs:*"
        Resource = aws_sqs_queue.public_queue.arn
      }
    ]
  })
}

resource "aws_launch_configuration" "unencrypted_launch_config" {
  name          = "unencrypted-launch-config"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  root_block_device {
    encrypted = false
  }

  associate_public_ip_address = true

  user_data = "export SECRET_KEY=my-secret-key-12345"
}

resource "aws_secretsmanager_secret" "public_secret" {
  name = "public-secret-${random_id.bucket_id.hex}"
}

resource "aws_secretsmanager_secret_policy" "public_secret_policy" {
  secret_arn = aws_secretsmanager_secret.public_secret.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action   = "secretsmanager:*"
        Resource = "*"
      }
    ]
  })
}
