import argparse

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest


DEFAULT_INPUT = "data/processed/cloudtrail_features.csv"
DEFAULT_OUTPUT = "data/processed/cloudtrail_anomaly_scores.csv"
DEFAULT_MODEL = "models/isolation_forest.joblib"

METADATA_COLUMNS = [
    "event_time",
    "event_source",
    "event_name",
    "user_name",
    "user_type",
    "error_code",
]


def load_dataset(path):
    return pd.read_csv(path)


def select_feature_columns(df):
    return [
        column
        for column in df.columns
        if column not in METADATA_COLUMNS
    ]


def train_model(features, contamination):
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )

    model.fit(features)
    return model


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

    if event_source == "iam.amazonaws.com" and event_name in iam_write_actions:
        if error_code == "AccessDenied":
            return "HIGH", "Denied IAM privilege modification attempt"

        return "HIGH", "IAM privilege modification event"

    if event_name == "CreateAccessKey":
        if error_code == "AccessDenied":
            return "HIGH", "Denied access key creation attempt"

        return "HIGH", "Access key creation event"

    if error_code == "AccessDenied":
        return "MEDIUM", "Access denied API call"

    if user_type == "Root" and pd.notna(error_code):
        return "MEDIUM", "Root activity with API error"

    if user_type == "Root":
        return "LOW", "Root account activity"

    return "LOW", "Statistical anomaly"


def score_events(model, df, feature_columns):
    features = df[feature_columns]

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
        description="Train Isolation Forest on CloudTrail features."
    )

    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--model-output", default=DEFAULT_MODEL)
    parser.add_argument("--contamination", type=float, default=0.05)

    return parser.parse_args()


def main():
    args = parse_args()

    dataset = load_dataset(args.input)
    feature_columns = select_feature_columns(dataset)

    features = dataset[feature_columns]

    model = train_model(features, args.contamination)
    results = score_events(model, dataset, feature_columns)

    results.to_csv(args.output, index=False)
    joblib.dump(model, args.model_output)

    print(f"Rows scored: {len(results)}")
    print(f"Feature columns: {len(feature_columns)}")
    print(f"Anomalies found: {results['is_anomaly'].sum()}")
    print(f"Saved scores to {args.output}")
    print(f"Saved model to {args.model_output}")

    print("\nTop 15 most anomalous events:")
    print(results.head(15).to_string(index=False))


if __name__ == "__main__":
    main()