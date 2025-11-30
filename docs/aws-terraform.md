# AWS CloudTrail → EventBridge → Kinesis (Terraform)

```hcl
variable "region" { default = "us-east-1" }
variable "stream_name" { default = "noclickops-stream" }
variable "rule_name" { default = "noclickops-cloudtrail-to-kinesis" }

provider "aws" {
  region = var.region
}

resource "aws_kinesis_stream" "this" {
  name = var.stream_name
  stream_mode_details { stream_mode = "ON_DEMAND" }
}

resource "aws_iam_role" "eb_kinesis" {
  name = "noclickops-eb-kinesis-${var.region}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "eb_kinesis" {
  role = aws_iam_role.eb_kinesis.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["kinesis:PutRecord", "kinesis:PutRecords"]
      Resource = aws_kinesis_stream.this.arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "cloudtrail" {
  name          = var.rule_name
  event_pattern = jsonencode({
    source        = ["aws.cloudtrail"]
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Action via CloudTrail"]
    detail = {
      eventSource = [{
        prefix = ""
      }]
    }
  })
}

resource "aws_cloudwatch_event_target" "kinesis" {
  rule      = aws_cloudwatch_event_rule.cloudtrail.name
  target_id = "kinesis"
  arn       = aws_kinesis_stream.this.arn
  role_arn  = aws_iam_role.eb_kinesis.arn

  kinesis_target {
    partition_key_path = "$.detail.eventID"
  }
}
```

Apply with:
```bash
terraform init
terraform apply -auto-approve
```
