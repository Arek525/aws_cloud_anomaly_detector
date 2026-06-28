import argparse

import pandas as pd


DEFAULT_INPUT = "data/processed/cloudtrail_anomaly_scores.csv"

KNOWN_SUSPICIOUS_EVENTS = {
    "CreateUser",
    "AttachUserPolicy",
    "CreateAccessKey",
}


def load_results(path):
    return pd.read_csv(path)


def add_known_suspicious_label(df):
    df = df.copy()

    df["is_known_suspicious"] = (
        (df["event_source"] == "iam.amazonaws.com")
        & (df["event_name"].isin(KNOWN_SUSPICIOUS_EVENTS))
        & (df["error_code"] == "AccessDenied")
    ).astype(int)

    return df


def precision_at_k(df, k):
    top_k = df.sort_values("anomaly_score", ascending=True).head(k)

    if len(top_k) == 0:
        return 0.0

    return top_k["is_known_suspicious"].mean()


def calculate_f1(precision, recall):
    if precision + recall == 0:
        return 0.0

    return 2 * precision * recall / (precision + recall)


def calculate_metrics(df):
    predicted_anomalies = df[df["is_anomaly"] == 1]
    known_suspicious = df[df["is_known_suspicious"] == 1]
    detected_known_suspicious = known_suspicious[
        known_suspicious["is_anomaly"] == 1
    ]

    if len(predicted_anomalies) > 0:
        precision = predicted_anomalies["is_known_suspicious"].mean()
    else:
        precision = 0.0

    if len(known_suspicious) > 0:
        recall = len(detected_known_suspicious) / len(known_suspicious)
    else:
        recall = 0.0

    high_alerts = df[
        (df["is_anomaly"] == 1)
        & (df["risk_level"] == "HIGH")
    ]

    detected_known_suspicious_high = known_suspicious[
        (known_suspicious["is_anomaly"] == 1)
        & (known_suspicious["risk_level"] == "HIGH")
    ]

    if len(high_alerts) > 0:
        high_precision = high_alerts["is_known_suspicious"].mean()
    else:
        high_precision = 0.0

    if len(known_suspicious) > 0:
        high_recall = len(detected_known_suspicious_high) / len(known_suspicious)
    else:
        high_recall = 0.0

    return {
        "total_events": len(df),
        "predicted_anomalies": len(predicted_anomalies),
        "known_suspicious": len(known_suspicious),
        "detected_known_suspicious": len(detected_known_suspicious),
        "precision": precision,
        "recall": recall,
        "f1_score": calculate_f1(precision, recall),
        "precision_at_10": precision_at_k(df, 10),
        "precision_at_20": precision_at_k(df, 20),
        "high_alerts": len(high_alerts),
        "detected_known_suspicious_high": len(detected_known_suspicious_high),
        "high_precision": high_precision,
        "high_recall": high_recall,
        "high_f1_score": calculate_f1(high_precision, high_recall),
    }


def print_metrics(metrics):
    print("Evaluation based on synthetic/pseudo labels")
    print("-------------------------------------------")
    print(f"Total events: {metrics['total_events']}")
    print(f"Predicted anomalies: {metrics['predicted_anomalies']}")
    print(f"Known suspicious events: {metrics['known_suspicious']}")
    print(f"Detected known suspicious: {metrics['detected_known_suspicious']}")
    print()
    print(f"Precision: {metrics['precision']:.2%}")
    print(f"Recall: {metrics['recall']:.2%}")
    print(f"F1 score: {metrics['f1_score']:.2%}")
    print(f"Precision@10: {metrics['precision_at_10']:.2%}")
    print(f"Precision@20: {metrics['precision_at_20']:.2%}")

    print()
    print("HIGH risk alert quality")
    print("-----------------------")
    print(f"HIGH alerts: {metrics['high_alerts']}")
    print(
        "Known suspicious in HIGH alerts: "
        f"{metrics['detected_known_suspicious_high']}"
    )
    print(f"HIGH precision: {metrics['high_precision']:.2%}")
    print(f"HIGH recall: {metrics['high_recall']:.2%}")
    print(f"HIGH F1 score: {metrics['high_f1_score']:.2%}")


def print_top_events(df):
    columns = [
        "event_time",
        "event_source",
        "event_name",
        "user_name",
        "error_code",
        "anomaly_score",
        "is_anomaly",
        "risk_level",
        "risk_reason",
        "is_known_suspicious",
    ]

    print("\nTop 20 ranked events:")
    print(
        df.sort_values("anomaly_score", ascending=True)[columns]
        .head(20)
        .to_string(index=False)
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Evaluate anomaly detection output against synthetic labels."
    )

    parser.add_argument("--input", default=DEFAULT_INPUT)

    return parser.parse_args()


def main():
    args = parse_args()

    results = load_results(args.input)
    results = add_known_suspicious_label(results)

    metrics = calculate_metrics(results)
    print_metrics(metrics)
    print_top_events(results)


if __name__ == "__main__":
    main()