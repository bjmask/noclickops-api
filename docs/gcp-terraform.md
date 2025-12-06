# GCP Audit Logs → Pub/Sub (Terraform)

```hcl
variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  default = "us-central1"
}

variable "topic_name" {
  default = "noclickops-audit-logs"
}

variable "subscription_name" {
  default = "noclickops-subscription"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Create Pub/Sub topic for audit logs
resource "google_pubsub_topic" "audit_logs" {
  name = var.topic_name
}

# Create subscription for the scanner to consume
resource "google_pubsub_subscription" "scanner" {
  name  = var.subscription_name
  topic = google_pubsub_topic.audit_logs.name

  ack_deadline_seconds = 20
  
  message_retention_duration = "604800s" # 7 days
  retain_acked_messages      = false
  
  expiration_policy {
    ttl = "" # Never expire
  }
}

# Create log sink to route audit logs to Pub/Sub
resource "google_logging_project_sink" "audit_logs" {
  name        = "noclickops-audit-sink"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.audit_logs.id}"
  
  # Filter for admin activity and data access logs
  filter = <<-EOT
    logName:"cloudaudit.googleapis.com"
    (protoPayload.methodName:* OR protoPayload.serviceName:*)
  EOT

  unique_writer_identity = true
}

# Grant the log sink permission to publish to Pub/Sub
resource "google_pubsub_topic_iam_member" "log_sink_publisher" {
  topic  = google_pubsub_topic.audit_logs.name
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.audit_logs.writer_identity
}

# Output the subscription name for scanner configuration
output "subscription_name" {
  value = google_pubsub_subscription.scanner.name
}

output "topic_name" {
  value = google_pubsub_topic.audit_logs.name
}
```

Apply with:
```bash
terraform init
terraform apply -auto-approve
```
