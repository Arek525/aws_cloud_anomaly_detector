import argparse
from pathlib import Path

import pandas as pd


DEFAULT_INPUT = "data/processed/cloudtrail_anomaly_scores.csv"
DEFAULT_OUTPUT = "reports/latest_alert.txt"


def load_results(path):
    return pd.read_csv(path)


def get_high_risk_anomalies(df):
    return df[
        (df["is_anomaly"] == 1)
        & (df["risk_level"] == "HIGH")
    ].copy()


def format_alert(high_risk_events):
    if high_risk_events.empty:
        return (
            "CloudTrail Guard Alert\n"
            "======================\n\n"
            "Status: OK\n"
            "No HIGH risk anomalies detected.\n"
        )

    lines = [
        "CloudTrail Guard Alert",
        "======================",
        "",
        "Status: HIGH RISK ACTIVITY DETECTED",
        f"High risk anomalies: {len(high_risk_events)}",
        "",
        "Detected events:",
    ]

    sorted_events = high_risk_events.sort_values(
        "anomaly_score",
        ascending=True,
    )

    for index, row in enumerate(sorted_events.itertuples(index=False), start=1):
        lines.extend([
            "",
            f"{index}. {row.event_name}",
            f"   Time: {row.event_time}",
            f"   Source: {row.event_source}",
            f"   User: {row.user_name}",
            f"   Error: {row.error_code}",
            f"   Risk: {row.risk_level}",
            f"   Reason: {row.risk_reason}",
            f"   Anomaly score: {row.anomaly_score:.6f}",
        ])

    return "\n".join(lines) + "\n"


def save_alert(message, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        file.write(message)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a readable alert from CloudTrail anomaly scores."
    )

    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)

    return parser.parse_args()


def main():
    args = parse_args()

    results = load_results(args.input)
    high_risk_events = get_high_risk_anomalies(results)

    message = format_alert(high_risk_events)
    save_alert(message, args.output)

    print(message)
    print(f"Saved alert to {args.output}")


if __name__ == "__main__":
    main()