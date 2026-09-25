"""Create Phase 3A dataset from preserved, real Phase 2 audit events."""
import csv
from pathlib import Path
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from src.ai.dataset import write_dataset
from src.ai.feature_extraction import extract_features

CONFIG = ROOT / "config" / "ai_feature_pipeline.yaml"


def main():
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    source = ROOT / config["pipeline"]["source_events"]
    if not source.exists(): raise SystemExit(f"No real Phase 2 audit log found at {source}; dataset was not created.")
    with source.open(newline="", encoding="utf-8") as stream: events = list(csv.DictReader(stream))
    rows = extract_features(events, config)
    files = write_dataset(rows, ROOT / config["pipeline"]["output_directory"], config, source)
    print(f"Phase 3A dataset created from {len(rows)} real Phase 2 events")
    for file in files: print(file)


if __name__ == "__main__": main()
