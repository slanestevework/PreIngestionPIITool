from scanner import scan_directory
import pandas as pd


if __name__ == "__main__":

    # <-- your sample folder
    path = "./data"

    findings, stats = scan_directory(path)

    findings_df = pd.DataFrame(findings)
    stats_df = pd.DataFrame(stats)

    print("\n=== Findings ===")
   

    display_columns = [
        "source",
        "column",
        "pattern",
        "risk",
        "confidence",
        "matches",
        "match_pct",
        "detection_source",
        "sample_match_1"
    ]

    print("\n=== Findings Summary ===")

    print(
        findings_df[display_columns]
        .sort_values(
            by=["risk", "detection_source", "source", "column"],
            ascending=[True, True, True, True]
        )
        .to_string(index=False)
    )

    print("\n=== Stats ===")
    print(stats_df)

    findings_df.to_csv(
        "pii_findings.csv",
        index=False
    )

    stats_df.to_csv(
        "pii_stats.csv",
        index=False
    )