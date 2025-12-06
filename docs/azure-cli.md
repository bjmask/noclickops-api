# Azure Activity Logs → Event Hub (CLI)

End-to-end example to stream activity logs from Azure Monitor into an Event Hub that feeds the scanner.

## Prereqs
- Azure CLI (`az`) configured
- Permissions to create Event Hubs and diagnostic settings
- Active Azure subscription

## Variables
```bash
export RESOURCE_GROUP=noclickops-rg
export LOCATION=eastus
export NAMESPACE_NAME=noclickops-eventhub-ns
export EVENTHUB_NAME=noclickops-activity-logs
export CONSUMER_GROUP=noclickops-scanner
export SUBSCRIPTION_ID=$(az account show --query id -o tsv)
```

## Create Resource Group
```bash
az group create \
  --name "$RESOURCE_GROUP" \
  --location "$LOCATION"
```

## Create Event Hub Namespace
```bash
az eventhubs namespace create \
  --name "$NAMESPACE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --sku Standard \
  --capacity 1
```

## Create Event Hub
```bash
az eventhubs eventhub create \
  --name "$EVENTHUB_NAME" \
  --namespace-name "$NAMESPACE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --partition-count 2 \
  --message-retention 7
```

## Create Consumer Group
```bash
az eventhubs eventhub consumer-group create \
  --name "$CONSUMER_GROUP" \
  --eventhub-name "$EVENTHUB_NAME" \
  --namespace-name "$NAMESPACE_NAME" \
  --resource-group "$RESOURCE_GROUP"
```

## Get Authorization Rule ID
```bash
export AUTH_RULE_ID=$(az eventhubs namespace authorization-rule show \
  --name RootManageSharedAccessKey \
  --namespace-name "$NAMESPACE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query id -o tsv)

echo "Authorization Rule ID: $AUTH_RULE_ID"
```

## Create Diagnostic Setting
Stream activity logs to Event Hub:
```bash
az monitor diagnostic-settings subscription create \
  --name noclickops-activity-logs \
  --location "$LOCATION" \
  --event-hub-name "$EVENTHUB_NAME" \
  --event-hub-auth-rule "$AUTH_RULE_ID" \
  --logs '[
    {"category": "Administrative", "enabled": true},
    {"category": "Security", "enabled": true},
    {"category": "Policy", "enabled": true},
    {"category": "Alert", "enabled": true}
  ]'
```

## Verify Setup
List Event Hubs:
```bash
az eventhubs eventhub list \
  --namespace-name "$NAMESPACE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --output table
```

List diagnostic settings:
```bash
az monitor diagnostic-settings subscription list \
  --output table
```

## Get Connection String
For scanner configuration:
```bash
az eventhubs namespace authorization-rule keys list \
  --name RootManageSharedAccessKey \
  --namespace-name "$NAMESPACE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query primaryConnectionString -o tsv
```

## Test
Trigger some activity in your Azure subscription (e.g., create a storage account) and verify events are flowing to the Event Hub.

Once the scanner is configured with the connection string, it will process incoming activity log events.
