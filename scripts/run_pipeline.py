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

    return parser.parse_args()


def main():
    args = parse_args()

    print("Starting CloudTrail Guard pipeline")
    print(f"Mode: {args.mode}")
    print(f"S3 log file limit: {args.limit}")
    print(f"AWS profile: {args.profile}")

    run_data_pipeline(limit=args.limit, profile=args.profile)
    run_feature_engineering()

    if args.mode == "train":
        run_training()
    elif args.mode == "detect":
        run_detection()

    print("\nPipeline finished successfully")


if __name__ == "__main__":
    main()