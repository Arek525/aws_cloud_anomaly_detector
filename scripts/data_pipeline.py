import argparse
import gzip
import json
from io import BytesIO

import boto3
import pandas as pd


DEFAULT_PROFILE = "cloudtrail-guard"
DEFAULT_REGION = "eu-central-1"
DEFAULT_BUCKET = "cloudtrail-guard-logs-755395261517"
DEFAULT_PREFIX = "AWSLogs/755395261517/CloudTrail/"
DEFAULT_OUTPUT = "data/processed/cloudtrail_events.csv"


def list_log_files(s3_client, bucket, prefix, limit):
    paginator = s3_client.get_paginator("list_objects_v2")
    files = []

    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for item in page.get("Contents", []):
            key = item["Key"]

            if key.endswith(".json.gz"):
                files.append(
                    {
                        "key": key,
                        "last_modified": item["LastModified"],
                    }
                )

    files.sort(key=lambda item: item["last_modified"], reverse=True)

    return [item["key"] for item in files[:limit]]


def read_cloudtrail_file(s3_client, bucket, key):
    response = s3_client.get_object(Bucket=bucket, Key=key)
    compressed_body = response["Body"].read()

    with gzip.GzipFile(fileobj=BytesIO(compressed_body)) as gzip_file:
        payload = json.loads(gzip_file.read().decode("utf-8"))

    return payload.get("Records", [])


def get_nested_value(data, path, default=None):
    value = data

    for part in path.split("."):
        if not isinstance(value, dict):
            return default

        value = value.get(part)

        if value is None:
            return default

    return value


def flatten_event(event, source_file):
    return {
        "source_file": source_file,
        "event_time": event.get("eventTime"),
        "event_source": event.get("eventSource"),
        "event_name": event.get("eventName"),
        "aws_region": event.get("awsRegion"),
        "source_ip": event.get("sourceIPAddress"),
        "user_agent": event.get("userAgent"),
        "read_only": event.get("readOnly"),
        "event_type": event.get("eventType"),
        "event_category": event.get("eventCategory"),
        "management_event": event.get("managementEvent"),
        "error_code": event.get("errorCode"),
        "error_message": event.get("errorMessage"),
        "user_type": get_nested_value(event, "userIdentity.type"),
        "user_name": get_nested_value(event, "userIdentity.userName"),
        "user_arn": get_nested_value(event, "userIdentity.arn"),
        "access_key_id": get_nested_value(event, "userIdentity.accessKeyId"),
        "mfa_authenticated": get_nested_value(
            event,
            "userIdentity.sessionContext.attributes.mfaAuthenticated",
        ),
    }


def build_dataset(session, bucket, prefix, limit):
    s3_client = session.client("s3")
    log_files = list_log_files(s3_client, bucket, prefix, limit)

    print(f"Found {len(log_files)} CloudTrail log files")

    rows = []

    for index, key in enumerate(log_files, start=1):
        print(f"[{index}/{len(log_files)}] Reading s3://{bucket}/{key}")

        records = read_cloudtrail_file(s3_client, bucket, key)

        for event in records:
            rows.append(flatten_event(event, key))

    return pd.DataFrame(rows)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Download CloudTrail logs from S3 and convert them to a CSV dataset."
    )

    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--bucket", default=DEFAULT_BUCKET)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)

    return parser.parse_args()


def main():
    args = parse_args()

    session = boto3.Session(
        profile_name=args.profile,
        region_name=args.region,
    )

    dataset = build_dataset(
        session=session,
        bucket=args.bucket,
        prefix=args.prefix,
        limit=args.limit,
    )

    print(f"Rows: {len(dataset)}")
    print(f"Columns: {list(dataset.columns)}")

    dataset.to_csv(args.output, index=False)
    print(f"Saved dataset to {args.output}")


if __name__ == "__main__":
    main()