provider "aws" {
  region = "ap-south-1" 
}

# 1. Create S3 Bucket
resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket-case-6" 
}

# S3 Bucket Policy to allow CloudTrail to write logs
resource "aws_s3_bucket_policy" "my_bucket_policy" {
  bucket = aws_s3_bucket.my_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck",
        Effect    = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action    = "s3:GetBucketAcl",
        Resource  = "arn:aws:s3:::${aws_s3_bucket.my_bucket.id}"
      },
      {
        Sid       = "AWSCloudTrailWrite",
        Effect    = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action    = "s3:PutObject",
        Resource  = "arn:aws:s3:::${aws_s3_bucket.my_bucket.id}/AWSLogs/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# 2. Create IAM Role and Attach Policies for EC2
resource "aws_iam_role" "ec2_role" {
  name = "ec2-s3-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_s3_access" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2_instance_profile"
  role = aws_iam_role.ec2_role.name
}

# 3. Create VPC, Subnet, and Security Group
resource "aws_vpc" "my_vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "my_subnet" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "ap-south-1a"
}

resource "aws_security_group" "ec2_sg" {
  name        = "ec2-security-group"
  description = "Allow SSH and S3 VPC endpoint access"
  vpc_id      = aws_vpc.my_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 4. Launch EC2 Instance with CloudWatch User Data
resource "aws_instance" "ec2_instance" {
  ami                         = "ami-0c2af51e265bd5e0e" 
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.my_subnet.id
  key_name                    = "case-6"  # Replace with your key-pair name
  iam_instance_profile        = aws_iam_instance_profile.ec2_instance_profile.name
  vpc_security_group_ids      = [aws_security_group.ec2_sg.id]

  # Install and configure the CloudWatch agent via user_data
  user_data = <<-EOF
  #!/bin/bash
  sudo yum update -y
  sudo yum install -y amazon-cloudwatch-agent

  # Create the CloudWatch agent configuration file
  cat <<EOL > /opt/aws/amazon-cloudwatch-agent/bin/config.json
  {
    "logs": {
      "logs_collected": {
        "files": {
          "collect_list": [
            {
              "file_path": "/var/log/messages",
              "log_group_name": "EC2LogGroup",
              "log_stream_name": "ec2-instance-log-stream"
            }
          ]
        }
      }
    }
  }
  EOL

  # Start the CloudWatch agent
  sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
      -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s
  EOF

  tags = {
    Name = "EC2InstanceWithS3Access"
  }
}

# 5. Create CloudWatch Log Group and Log Stream
resource "aws_cloudwatch_log_group" "ec2_log_group" {
  name              = "EC2LogGroup"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_stream" "ec2_log_stream" {
  log_group_name = aws_cloudwatch_log_group.ec2_log_group.name
  name           = "EC2LogStream"
}

# 6. Create CloudTrail for EC2 Logging
resource "aws_cloudtrail" "ec2_trail" {
  name                          = "EC2ActivityTrail"
  s3_bucket_name                = aws_s3_bucket.my_bucket.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

# 7. Create a VPC Endpoint for S3
resource "aws_vpc_endpoint" "s3_endpoint" {
  vpc_id       = aws_vpc.my_vpc.id
  service_name = "com.amazonaws.ap-south-1.s3"  
  route_table_ids = [aws_route_table.my_route_table.id]
}

# 8. Create a Route Table
resource "aws_route_table" "my_route_table" {
  vpc_id = aws_vpc.my_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.my_gw.id
  }
}

# 9. Create an Internet Gateway
resource "aws_internet_gateway" "my_gw" {
  vpc_id = aws_vpc.my_vpc.id
}

# Optional Output to View Resources
output "ec2_instance_public_ip" {
  description = "Public IP of the EC2 instance"
  value       = aws_instance.ec2_instance.public_ip
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket"
  value       = aws_s3_bucket.my_bucket.bucket
}
