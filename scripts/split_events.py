import argparse
from pathlib import Path

import pandas as pd


DEFAULT_INPUT = "data/processed/cloudtrail_events.csv"
DEFAULT_TRAIN_OUTPUT = "data/processed/train_events.csv"
DEFAULT_DETECT_OUTPUT = "data/processed/detect_events.csv"

KNOWN_SUSPICIOUS_EVENTS = {
    "CreateUser",
    "AttachUserPolicy",
    "CreateAccessKey",
}


def load_events(path):
    return pd.read_csv(path)


def add_known_suspicious_label(df):
    df = df.copy()

    df["is_known_suspicious"] = (
        (df["event_source"] == "iam.amazonaws.com")
        & (df["event_name"].isin(KNOWN_SUSPICIOUS_EVENTS))
        & (df["error_code"] == "AccessDenied")
    ).astype(int)

    return df


def split_by_cutoff(df, cutoff):
    event_time = pd.to_datetime(df["event_time"], errors="coerce", utc=True)
    cutoff_time = pd.to_datetime(cutoff, utc=True)

    train_df = df[event_time < cutoff_time].copy()
    detect_df = df[event_time >= cutoff_time].copy()

    return train_df, detect_df


def split_by_ratio(df, train_ratio):
    df = df.copy()
    df["event_time_parsed"] = pd.to_datetime(
        df["event_time"],
        errors="coerce",
        utc=True,
    )

    df = df.sort_values("event_time_parsed")
    split_index = int(len(df) * train_ratio)

    train_df = df.iloc[:split_index].copy()
    detect_df = df.iloc[split_index:].copy()

    train_df = train_df.drop(columns=["event_time_parsed"])
    detect_df = detect_df.drop(columns=["event_time_parsed"])

    return train_df, detect_df


def remove_known_suspicious_from_train(train_df):
    before_count = len(train_df)
    train_df = train_df[train_df["is_known_suspicious"] == 0].copy()
    removed_count = before_count - len(train_df)

    return train_df, removed_count


def save_dataset(df, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Split CloudTrail events into training and detection windows."
    )

    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--train-output", default=DEFAULT_TRAIN_OUTPUT)
    parser.add_argument("--detect-output", default=DEFAULT_DETECT_OUTPUT)
    parser.add_argument("--cutoff")
    parser.add_argument("--train-ratio", type=float, default=0.7)
    parser.add_argument(
        "--drop-known-suspicious-from-train",
        action="store_true",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    events = load_events(args.input)
    events = add_known_suspicious_label(events)

    if args.cutoff:
        train_events, detect_events = split_by_cutoff(events, args.cutoff)
        split_description = f"cutoff={args.cutoff}"
    else:
        train_events, detect_events = split_by_ratio(events, args.train_ratio)
        split_description = f"train_ratio={args.train_ratio}"

    removed_count = 0

    if args.drop_known_suspicious_from_train:
        train_events, removed_count = remove_known_suspicious_from_train(train_events)

    save_dataset(train_events, args.train_output)
    save_dataset(detect_events, args.detect_output)

    print("Event split complete")
    print(f"Split strategy: {split_description}")
    print(f"Input rows: {len(events)}")
    print(f"Train rows: {len(train_events)}")
    print(f"Detect rows: {len(detect_events)}")
    print(f"Known suspicious in train: {train_events['is_known_suspicious'].sum()}")
    print(f"Known suspicious in detect: {detect_events['is_known_suspicious'].sum()}")
    print(f"Removed from train: {removed_count}")
    print(f"Saved train events to {args.train_output}")
    print(f"Saved detect events to {args.detect_output}")


if __name__ == "__main__":
    main()