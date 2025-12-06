# GCP Audit Logs → Pub/Sub (CLI)

End-to-end example to stream audit logs from GCP Cloud Audit Logs into a Pub/Sub topic that feeds the scanner.

## Prereqs
- `gcloud` CLI configured
- Permissions to create Pub/Sub topics/subscriptions and logging sinks
- Project with Cloud Audit Logs enabled

## Variables
```bash
export PROJECT_ID=$(gcloud config get-value project)
export REGION=us-central1
export TOPIC_NAME=noclickops-audit-logs
export SUBSCRIPTION_NAME=noclickops-subscription
export SINK_NAME=noclickops-audit-sink
```

## Create Pub/Sub Topic
```bash
gcloud pubsub topics create "$TOPIC_NAME" \
  --project="$PROJECT_ID"
```

## Create Subscription
```bash
gcloud pubsub subscriptions create "$SUBSCRIPTION_NAME" \
  --topic="$TOPIC_NAME" \
  --ack-deadline=20 \
  --message-retention-duration=7d \
  --project="$PROJECT_ID"
```

## Create Log Sink
Create a sink to route audit logs to Pub/Sub:
```bash
gcloud logging sinks create "$SINK_NAME" \
  "pubsub.googleapis.com/projects/$PROJECT_ID/topics/$TOPIC_NAME" \
  --log-filter='logName:"cloudaudit.googleapis.com" (protoPayload.methodName:* OR protoPayload.serviceName:*)' \
  --project="$PROJECT_ID"
```

## Grant Permissions
Get the service account created by the log sink:
```bash
export SINK_SA=$(gcloud logging sinks describe "$SINK_NAME" \
  --project="$PROJECT_ID" \
  --format='value(writerIdentity)')

echo "Sink service account: $SINK_SA"
```

Grant the sink permission to publish to Pub/Sub:
```bash
gcloud pubsub topics add-iam-policy-binding "$TOPIC_NAME" \
  --member="$SINK_SA" \
  --role="roles/pubsub.publisher" \
  --project="$PROJECT_ID"
```

## Verify Setup
Check that the topic exists:
```bash
gcloud pubsub topics describe "$TOPIC_NAME" --project="$PROJECT_ID"
```

Check that the subscription exists:
```bash
gcloud pubsub subscriptions describe "$SUBSCRIPTION_NAME" --project="$PROJECT_ID"
```

List log sinks:
```bash
gcloud logging sinks list --project="$PROJECT_ID"
```

## Test
Trigger some activity in your GCP project (e.g., create a storage bucket) and verify messages appear:
```bash
gcloud pubsub subscriptions pull "$SUBSCRIPTION_NAME" \
  --limit=5 \
  --project="$PROJECT_ID"
```

Once the scanner is configured to consume from this subscription, it will process incoming audit events.
