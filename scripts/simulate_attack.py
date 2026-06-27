import argparse
import time

import boto3
from botocore.exceptions import ClientError


DEFAULT_PROFILE = "cloudtrail-guard"
DEFAULT_REGION = "eu-central-1"


def run_api_call(name, call):
    print(f"[RUN] {name}")

    try:
        call()
        print(f"[OK]  {name}")
    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code", "Unknown")
        error_message = error.response.get("Error", {}).get("Message", "")
        print(f"[ERR] {name} -> {error_code}: {error_message}")

    time.sleep(0.4)


def run_normal_activity(session):
    print("\n=== Normal read-only activity ===")

    sts = session.client("sts")
    iam = session.client("iam")
    s3 = session.client("s3")
    ec2 = session.client("ec2")

    calls = [
        ("sts:GetCallerIdentity", sts.get_caller_identity),
        ("iam:GetAccountSummary", iam.get_account_summary),
        ("iam:ListUsers", lambda: iam.list_users(MaxItems=10)),
        ("iam:ListRoles", lambda: iam.list_roles(MaxItems=10)),
        ("iam:ListPolicies", lambda: iam.list_policies(Scope="Local", MaxItems=10)),
        ("s3:ListBuckets", s3.list_buckets),
        ("ec2:DescribeRegions", ec2.describe_regions),
        ("ec2:DescribeInstances", lambda: ec2.describe_instances(MaxResults=10)),
        ("ec2:DescribeSecurityGroups", lambda: ec2.describe_security_groups(MaxResults=10)),
    ]

    for name, call in calls:
        run_api_call(name, call)


def run_recon_burst(session, rounds):
    print("\n=== Reconnaissance burst ===")

    iam = session.client("iam")
    s3 = session.client("s3")
    ec2 = session.client("ec2")

    calls = [
        ("iam:ListUsers", lambda: iam.list_users(MaxItems=10)),
        ("iam:ListRoles", lambda: iam.list_roles(MaxItems=10)),
        ("iam:ListPolicies", lambda: iam.list_policies(Scope="AWS", MaxItems=10)),
        ("s3:ListBuckets", s3.list_buckets),
        ("ec2:DescribeSecurityGroups", lambda: ec2.describe_security_groups(MaxResults=10)),
    ]

    for round_number in range(1, rounds + 1):
        print(f"\nRecon round {round_number}/{rounds}")

        for name, call in calls:
            run_api_call(name, call)


def run_blocked_privilege_attempts(session):
    print("\n=== Blocked privilege escalation attempts ===")

    iam = session.client("iam")
    test_user_name = f"blocked-test-user-{int(time.time())}"

    calls = [
        ("iam:CreateUser", lambda: iam.create_user(UserName=test_user_name)),
        (
            "iam:AttachUserPolicy",
            lambda: iam.attach_user_policy(
                UserName="cloudtrail-guard-boto3",
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            ),
        ),
        (
            "iam:CreateAccessKey",
            lambda: iam.create_access_key(UserName="cloudtrail-guard-boto3"),
        ),
    ]

    for name, call in calls:
        run_api_call(name, call)


def run_selected_mode(session, mode, burst_rounds):
    if mode == "normal":
        run_normal_activity(session)
    elif mode == "recon":
        run_recon_burst(session, burst_rounds)
    elif mode == "denied":
        run_blocked_privilege_attempts(session)
    elif mode == "all":
        run_normal_activity(session)
        run_recon_burst(session, burst_rounds)
        run_blocked_privilege_attempts(session)
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate CloudTrail events for anomaly detection."
    )

    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--burst-rounds", type=int, default=3)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument(
        "--mode",
        choices=["normal", "recon", "denied", "all"],
        default="all",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    session = boto3.Session(
        profile_name=args.profile,
        region_name=args.region,
    )

    print("Starting CloudTrail event simulation")
    print(f"Profile: {args.profile}")
    print(f"Region: {args.region}")
    print(f"Mode: {args.mode}")
    print(f"Repeat: {args.repeat}")

    for run_number in range(1, args.repeat + 1):
        print(f"\n--- Simulation run {run_number}/{args.repeat} ---")
        run_selected_mode(session, args.mode, args.burst_rounds)

    print("\nDone. CloudTrail can take a few minutes to deliver logs to S3.")


if __name__ == "__main__":
    main()