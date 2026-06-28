import argparse
import subprocess
import sys


DEFAULT_LIMIT = 100
DEFAULT_PROFILE = "cloudtrail-guard"


def run_command(command):
    print("\nRunning command:")
    print(" ".join(command))

    completed_process = subprocess.run(command, check=False)

    if completed_process.returncode != 0:
        raise SystemExit(completed_process.returncode)


def run_data_pipeline(limit, profile):
    run_command([
        sys.executable,
        "scripts/data_pipeline.py",
        "--limit",
        str(limit),
        "--profile",
        profile,
    ])


def run_feature_engineering():
    run_command([
        sys.executable,
        "scripts/feature_engineering.py",
    ])


def run_training():
    run_command([
        sys.executable,
        "scripts/train_model.py",
    ])


def run_detection():
    run_command([
        sys.executable,
        "scripts/run_detection.py",
    ])


def run_evaluation():
    run_command([
        sys.executable,
        "scripts/evaluate_results.py",
    ])


def run_alert_generation():
    run_command([
        sys.executable,
        "scripts/generate_alerts.py",
    ])


def run_alert_publish(profile):
    run_command([
        sys.executable,
        "scripts/publish_alert.py",
        "--profile",
        profile,
    ])


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the CloudTrail anomaly detection pipeline."
    )

    parser.add_argument(
        "--mode",
        choices=["train", "detect"],
        required=True,
    )
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument(
        "--evaluate",
        action="store_true",
        help="Run pseudo-label evaluation after detection.",
    )
    parser.add_argument(
        "--alert",
        action="store_true",
        help="Generate HIGH risk alert output after detection.",
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish generated HIGH risk alert to SNS.",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    print("Starting CloudTrail Guard pipeline")
    print(f"Mode: {args.mode}")
    print(f"S3 log file limit: {args.limit}")
    print(f"AWS profile: {args.profile}")
    print(f"Evaluation enabled: {args.evaluate}")
    print(f"Alert generation enabled: {args.alert}")
    print(f"SNS publish enabled: {args.publish}")

    run_data_pipeline(limit=args.limit, profile=args.profile)
    run_feature_engineering()

    if args.mode == "train":
        if args.evaluate:
            raise SystemExit("--evaluate can only be used with --mode detect")
        if args.alert:
            raise SystemExit("--alert can only be used with --mode detect")
        if args.publish:
            raise SystemExit("--publish can only be used with --mode detect")

        run_training()
    elif args.mode == "detect":
        run_detection()

        if args.evaluate:
            run_evaluation()

        if args.alert or args.publish:
            run_alert_generation()

        if args.publish:
            run_alert_publish(args.profile)

    print("\nPipeline finished successfully")


if __name__ == "__main__":
    main()