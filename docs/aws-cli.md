# AWS CloudTrail → EventBridge → Kinesis (CLI)

End-to-end example to stream management events from CloudTrail into a Kinesis Data Stream that feeds the scanner.

## Prereqs
- AWS CLI configured
- Permissions to create Kinesis, IAM role/policy, and EventBridge rules/targets

## Variables
```bash
export REGION=us-east-1            # use your trail's home region
export ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
export STREAM=noclickops-stream
export ROLE_NAME=noclickops-eb-kinesis-$REGION
export RULE_NAME=noclickops-cloudtrail-to-kinesis
```

## Create the Stream (on-demand)
```bash
aws kinesis create-stream \
  --stream-name "$STREAM" \
  --stream-mode-details StreamMode=ON_DEMAND \
  --region "$REGION"

aws kinesis wait stream-exists --stream-name "$STREAM" --region "$REGION"
```

## IAM Role for EventBridge Target
```bash
cat > /tmp/eb-trust.json <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF

aws iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document file:///tmp/eb-trust.json

cat > /tmp/eb-kinesis-policy.json <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["kinesis:PutRecord","kinesis:PutRecords"],"Resource":"arn:aws:kinesis:$REGION:$ACCOUNT:stream/$STREAM"}]}
EOF

aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "${ROLE_NAME}-inline" \
  --policy-document file:///tmp/eb-kinesis-policy.json
```

## EventBridge Rule (CloudTrail + Console Actions)
```bash
aws events put-rule \
  --name "$RULE_NAME" \
  --region "$REGION" \
  --event-pattern '{"source":["aws.cloudtrail"],"detail-type":["AWS API Call via CloudTrail","AWS Console Action via CloudTrail"],"detail":{"eventSource":[{"prefix":""}]}}'
```

## EventBridge Target → Kinesis
Partition on `eventID` to spread load.
```bash
aws events put-targets \
  --region "$REGION" \
  --rule "$RULE_NAME" \
  --targets "[
    {
      \"Id\": \"kinesis\",
      \"Arn\": \"arn:aws:kinesis:$REGION:$ACCOUNT:stream/$STREAM\",
      \"RoleArn\": \"arn:aws:iam::$ACCOUNT:role/$ROLE_NAME\",
      \"KinesisParameters\": {\"PartitionKeyPath\": \"$.detail.eventID\"}
    }
  ]"
```

## Verify events
```bash
aws kinesis list-shards --stream-name "$STREAM" --region "$REGION"
```

Once the scanner consumes from Kinesis, it will classify incoming events.
