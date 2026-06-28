import argparse
from pathlib import Path

import pandas as pd


DEFAULT_INPUT = "data/processed/cloudtrail_anomaly_scores.csv"
DEFAULT_OUTPUT = "reports/latest_alert.txt"
DEFAULT_STATE_FILE = "state/alerted_event_ids.txt"


def load_results(path):
    return pd.read_csv(path)


def load_alerted_event_ids(path):
    state_path = Path(path)

    if not state_path.exists():
        return set()

    return {
        line.strip()
        for line in state_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def save_alerted_event_ids(event_ids, path):
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)

    existing_ids = load_alerted_event_ids(path)
    updated_ids = existing_ids.union(event_ids)

    state_path.write_text(
        "\n".join(sorted(updated_ids)) + "\n",
        encoding="utf-8",
    )


def get_high_risk_anomalies(df, alerted_event_ids):
    high_risk_events = df[
        (df["is_anomaly"] == 1)
        & (df["risk_level"] == "HIGH")
    ].copy()

    high_risk_events["event_id"] = high_risk_events["event_id"].fillna("")

    return high_risk_events[
        ~high_risk_events["event_id"].isin(alerted_event_ids)
    ].copy()


def format_alert(high_risk_events):
    if high_risk_events.empty:
        return (
            "CloudTrail Guard Alert\n"
            "======================\n\n"
            "Status: OK\n"
            "No new HIGH risk anomalies detected.\n"
        )

    lines = [
        "CloudTrail Guard Alert",
        "======================",
        "",
        "Status: HIGH RISK ACTIVITY DETECTED",
        f"New high risk anomalies: {len(high_risk_events)}",
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
            f"   Event ID: {row.event_id}",
            f"   Request ID: {row.request_id}",
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
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(message, encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a readable alert from CloudTrail anomaly scores."
    )

    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--state-file", default=DEFAULT_STATE_FILE)

    return parser.parse_args()


def main():
    args = parse_args()

    results = load_results(args.input)
    alerted_event_ids = load_alerted_event_ids(args.state_file)
    high_risk_events = get_high_risk_anomalies(results, alerted_event_ids)

    message = format_alert(high_risk_events)
    save_alert(message, args.output)

    new_event_ids = set(high_risk_events["event_id"].dropna())
    new_event_ids = {event_id for event_id in new_event_ids if event_id}

    if new_event_ids:
        save_alerted_event_ids(new_event_ids, args.state_file)

    print(message)
    print(f"Saved alert to {args.output}")
    print(f"New alerted events: {len(new_event_ids)}")


if __name__ == "__main__":
    main()