import argparse
import subprocess
import sys


DEFAULT_LIMIT = 200
DEFAULT_PROFILE = "cloudtrail-guard"
DEFAULT_TRAIN_RATIO = 0.7


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


def run_split(train_ratio):
    run_command([
        sys.executable,
        "scripts/split_events.py",
        "--train-ratio",
        str(train_ratio),
        "--drop-known-suspicious-from-train",
    ])


def run_train_features():
    run_command([
        sys.executable,
        "scripts/feature_engineering.py",
        "--input",
        "data/processed/train_events.csv",
        "--output",
        "data/processed/train_features.csv",
    ])


def run_detect_features():
    run_command([
        sys.executable,
        "scripts/feature_engineering.py",
        "--input",
        "data/processed/detect_events.csv",
        "--output",
        "data/processed/detect_features.csv",
    ])


def run_training():
    run_command([
        sys.executable,
        "scripts/train_model.py",
        "--input",
        "data/processed/train_features.csv",
        "--output",
        "data/processed/training_anomaly_scores.csv",
    ])


def run_detection():
    run_command([
        sys.executable,
        "scripts/run_detection.py",
        "--input",
        "data/processed/detect_features.csv",
        "--output",
        "data/processed/cloudtrail_anomaly_scores.csv",
    ])


def run_evaluation():
    run_command([
        sys.executable,
        "scripts/evaluate_results.py",
        "--input",
        "data/processed/cloudtrail_anomaly_scores.csv",
    ])


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run a train/detect split experiment for CloudTrail anomaly detection."
    )

    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--train-ratio", type=float, default=DEFAULT_TRAIN_RATIO)

    return parser.parse_args()


def main():
    args = parse_args()

    print("Starting CloudTrail Guard evaluation experiment")
    print(f"S3 log file limit: {args.limit}")
    print(f"AWS profile: {args.profile}")
    print(f"Train ratio: {args.train_ratio}")

    run_data_pipeline(limit=args.limit, profile=args.profile)
    run_split(train_ratio=args.train_ratio)
    run_train_features()
    run_detect_features()
    run_training()
    run_detection()
    run_evaluation()

    print("\nExperiment finished successfully")


if __name__ == "__main__":
    main()