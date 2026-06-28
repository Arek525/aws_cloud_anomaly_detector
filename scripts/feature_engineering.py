import argparse

import pandas as pd


DEFAULT_INPUT = "data/processed/cloudtrail_events.csv"
DEFAULT_OUTPUT = "data/processed/cloudtrail_features.csv"


CATEGORICAL_COLUMNS = [
    "event_source",
    "event_name",
    "aws_region",
    "user_type",
    "error_code",
]


def load_events(path):
    return pd.read_csv(path)


def add_basic_features(df):
    features = pd.DataFrame(index=df.index)

    event_time = pd.to_datetime(df["event_time"], errors="coerce", utc=True)

    features["event_hour"] = event_time.dt.hour.fillna(0).astype(int)
    features["event_day_of_week"] = event_time.dt.dayofweek.fillna(0).astype(int)
    features["is_weekend"] = (features["event_day_of_week"] >= 5).astype(int)

    features["is_read_only"] = df["read_only"].fillna(False).astype(bool).astype(int)
    features["is_management_event"] = (
        df["management_event"].fillna(False).astype(bool).astype(int)
    )
    features["has_error"] = df["error_code"].notna().astype(int)

    event_name = df["event_name"].fillna("")
    event_source = df["event_source"].fillna("")
    error_code = df["error_code"].fillna("")
    user_agent = df["user_agent"].fillna("")

    sensitive_iam_actions = {
        "CreateUser",
        "AttachUserPolicy",
        "CreateAccessKey",
        "PutUserPolicy",
        "CreatePolicy",
        "CreateRole",
        "UpdateAssumeRolePolicy",
    }

    features["is_access_denied"] = (error_code == "AccessDenied").astype(int)
    features["is_iam_event"] = (event_source == "iam.amazonaws.com").astype(int)
    features["is_iam_write_event"] = (
        (event_source == "iam.amazonaws.com")
        & (~df["read_only"].fillna(False).astype(bool))
    ).astype(int)
    features["is_sensitive_iam_action"] = event_name.isin(
        sensitive_iam_actions
    ).astype(int)
    features["is_access_key_action"] = event_name.str.contains(
        "AccessKey",
        case=False,
    ).astype(int)
    features["is_policy_action"] = event_name.str.contains(
        "Policy",
        case=False,
    ).astype(int)

    features["is_boto3_user_agent"] = user_agent.str.contains(
        "Boto3",
        case=False,
    ).astype(int)
    features["is_aws_cli_user_agent"] = user_agent.str.contains(
        "aws-cli",
        case=False,
    ).astype(int)
    features["is_console_user_agent"] = user_agent.str.contains(
        "Mozilla",
        case=False,
    ).astype(int)

    features["is_root_user"] = (df["user_type"] == "Root").astype(int)
    features["is_iam_user"] = (df["user_type"] == "IAMUser").astype(int)
    features["is_aws_service"] = (df["user_type"] == "AWSService").astype(int)

    return features


def add_categorical_features(df):
    categorical = df[CATEGORICAL_COLUMNS].fillna("None")

    encoded = pd.get_dummies(
        categorical,
        columns=CATEGORICAL_COLUMNS,
        prefix=CATEGORICAL_COLUMNS,
        dtype=int,
    )

    return encoded


def build_features(df):
    basic_features = add_basic_features(df)
    categorical_features = add_categorical_features(df)

    features = pd.concat([basic_features, categorical_features], axis=1)

    metadata = df[
        [
            "event_id",
            "request_id",
            "event_time",
            "event_source",
            "event_name",
            "user_name",
            "user_type",
            "error_code",
        ]
    ].copy()

    return metadata, features


def parse_args():
    parser = argparse.ArgumentParser(
        description="Create numeric features from flattened CloudTrail events."
    )

    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)

    return parser.parse_args()


def main():
    args = parse_args()

    events = load_events(args.input)
    metadata, features = build_features(events)

    dataset = pd.concat([metadata, features], axis=1)
    dataset.to_csv(args.output, index=False)

    print(f"Input rows: {len(events)}")
    print(f"Feature columns: {features.shape[1]}")
    print(f"Saved features to {args.output}")


if __name__ == "__main__":
    main()