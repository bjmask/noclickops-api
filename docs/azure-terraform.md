# Azure Activity Logs → Event Hub (Terraform)

```hcl
variable "resource_group_name" {
  description = "Resource group name"
  type        = string
  default     = "noclickops-rg"
}

variable "location" {
  default = "eastus"
}

variable "namespace_name" {
  default = "noclickops-eventhub-ns"
}

variable "eventhub_name" {
  default = "noclickops-activity-logs"
}

provider "azurerm" {
  features {}
}

# Create resource group
resource "azurerm_resource_group" "this" {
  name     = var.resource_group_name
  location = var.location
}

# Create Event Hub namespace
resource "azurerm_eventhub_namespace" "this" {
  name                = var.namespace_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "Standard"
  capacity            = 1
}

# Create Event Hub
resource "azurerm_eventhub" "activity_logs" {
  name                = var.eventhub_name
  namespace_name      = azurerm_eventhub_namespace.this.name
  resource_group_name = azurerm_resource_group.this.name
  partition_count     = 2
  message_retention   = 7
}

# Create consumer group for the scanner
resource "azurerm_eventhub_consumer_group" "scanner" {
  name                = "noclickops-scanner"
  namespace_name      = azurerm_eventhub_namespace.this.name
  eventhub_name       = azurerm_eventhub.activity_logs.name
  resource_group_name = azurerm_resource_group.this.name
}

# Get current subscription
data "azurerm_subscription" "current" {}

# Create diagnostic setting to stream activity logs
resource "azurerm_monitor_diagnostic_setting" "activity_logs" {
  name                       = "noclickops-activity-logs"
  target_resource_id         = data.azurerm_subscription.current.id
  eventhub_name              = azurerm_eventhub.activity_logs.name
  eventhub_authorization_rule_id = azurerm_eventhub_namespace.this.default_primary_connection_string

  enabled_log {
    category = "Administrative"
  }

  enabled_log {
    category = "Security"
  }

  enabled_log {
    category = "Policy"
  }

  enabled_log {
    category = "Alert"
  }
}

# Output connection details
output "eventhub_namespace" {
  value = azurerm_eventhub_namespace.this.name
}

output "eventhub_name" {
  value = azurerm_eventhub.activity_logs.name
}

output "consumer_group" {
  value = azurerm_eventhub_consumer_group.scanner.name
}
```

Apply with:
```bash
terraform init
terraform apply -auto-approve
```
