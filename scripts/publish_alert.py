import argparse
import os
from pathlib import Path

import boto3


DEFAULT_PROFILE = "cloudtrail-guard"
DEFAULT_REGION = "eu-central-1"
DEFAULT_ALERT_FILE = "reports/latest_alert.txt"
DEFAULT_TOPIC_ARN = os.getenv("CLOUDTRAIL_GUARD_SNS_TOPIC_ARN")


def load_alert(path):
    return Path(path).read_text(encoding="utf-8")


def publish_alert(profile, region, topic_arn, subject, message):
    session = boto3.Session(
        profile_name=profile,
        region_name=region,
    )
    sns = session.client("sns")

    response = sns.publish(
        TopicArn=topic_arn,
        Subject=subject,
        Message=message,
    )

    return response["MessageId"]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Publish CloudTrail Guard alert to SNS."
    )

    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--topic-arn", default=DEFAULT_TOPIC_ARN)
    parser.add_argument("--alert-file", default=DEFAULT_ALERT_FILE)
    parser.add_argument(
        "--subject",
        default="CloudTrail Guard HIGH Risk Alert",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if not args.topic_arn:
        raise SystemExit(
            "Missing SNS topic ARN. Pass --topic-arn or set "
            "CLOUDTRAIL_GUARD_SNS_TOPIC_ARN."
        )

    message = load_alert(args.alert_file)

    if "HIGH RISK ACTIVITY DETECTED" not in message:
        print("No HIGH risk alert found. SNS notification skipped.")
        return

    message_id = publish_alert(
        profile=args.profile,
        region=args.region,
        topic_arn=args.topic_arn,
        subject=args.subject,
        message=message,
    )

    print(f"Published SNS alert. MessageId: {message_id}")


if __name__ == "__main__":
    main()