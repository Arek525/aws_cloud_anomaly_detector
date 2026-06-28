import argparse
import json

import joblib
import pandas as pd


DEFAULT_INPUT = "data/processed/cloudtrail_features.csv"
DEFAULT_OUTPUT = "data/processed/cloudtrail_anomaly_scores.csv"
DEFAULT_MODEL = "models/isolation_forest.joblib"
DEFAULT_FEATURE_COLUMNS = "models/feature_columns.json"

METADATA_COLUMNS = [
    "event_id",
    "request_id",
    "event_time",
    "event_source",
    "event_name",
    "user_name",
    "user_type",
    "error_code",
]


def load_dataset(path):
    return pd.read_csv(path)


def load_feature_columns(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def align_features(df, feature_columns):
    return df.reindex(columns=feature_columns, fill_value=0)


def classify_risk(row):
    event_source = row.get("event_source")
    event_name = row.get("event_name")
    user_type = row.get("user_type")
    error_code = row.get("error_code")

    iam_write_actions = {
        "CreateUser",
        "AttachUserPolicy",
        "CreateAccessKey",
        "PutUserPolicy",
        "CreatePolicy",
        "CreateRole",
        "UpdateAssumeRolePolicy",
    }

    if event_name == "CreateAccessKey":
        if error_code == "AccessDenied":
            return "HIGH", "Denied access key creation attempt"

        return "HIGH", "Access key creation event"

    if event_source == "iam.amazonaws.com" and event_name in iam_write_actions:
        if error_code == "AccessDenied":
            return "HIGH", "Denied IAM privilege modification attempt"

        return "HIGH", "IAM privilege modification event"

    if error_code == "AccessDenied":
        return "MEDIUM", "Access denied API call"

    if user_type == "Root" and pd.notna(error_code):
        return "MEDIUM", "Root activity with API error"

    if user_type == "Root":
        return "LOW", "Root account activity"

    return "LOW", "Statistical anomaly"


def score_events(model, df, features):
    results = df[METADATA_COLUMNS].copy()
    results["anomaly_score"] = model.decision_function(features)
    results["is_anomaly"] = model.predict(features)

    results["is_anomaly"] = results["is_anomaly"].map({
        1: 0,
        -1: 1,
    })

    risk_labels = results.apply(classify_risk, axis=1)
    results["risk_level"] = [label[0] for label in risk_labels]
    results["risk_reason"] = [label[1] for label in risk_labels]

    return results.sort_values("anomaly_score", ascending=True)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run anomaly detection with a trained Isolation Forest model."
    )

    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--feature-columns", default=DEFAULT_FEATURE_COLUMNS)

    return parser.parse_args()


def main():
    args = parse_args()

    dataset = load_dataset(args.input)
    model = joblib.load(args.model)
    feature_columns = load_feature_columns(args.feature_columns)
    features = align_features(dataset, feature_columns)

    results = score_events(model, dataset, features)
    results.to_csv(args.output, index=False)

    print(f"Rows scored: {len(results)}")
    print(f"Feature columns used: {len(feature_columns)}")
    print(f"Anomalies found: {results['is_anomaly'].sum()}")
    print(f"Saved scores to {args.output}")

    print("\nTop 15 detected anomalies:")
    print(results.head(15).to_string(index=False))


if __name__ == "__main__":
    main()