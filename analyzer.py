"""Normalize, deduplicate and order CloudTrail events into an investigation timeline."""

from datetime import datetime, timezone

def analyze(data):
    timeline, seen = [], set()
    for index, e in enumerate(data.get("Records", [])):
        event_id = e.get("eventID")
        if event_id and event_id in seen:
            continue
        if event_id:
            seen.add(event_id)
        parsed = datetime.fromisoformat(e["eventTime"].replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("eventTime requires a timezone")
        timeline.append({"resource": event_id or f"record-{index}", "severity": "INFO", "check": "TIMELINE_EVENT",
                         "timestamp": parsed.astimezone(timezone.utc).isoformat(),
                         "identity": e.get("userIdentity", {}).get("arn", e.get("userIdentity", {}).get("type", "unknown")),
                         "action": e.get("eventName"), "source_ip": e.get("sourceIPAddress"),
                         "outcome": "failure" if e.get("errorCode") else "success",
                         "detail": "Normalized event; inclusion does not imply malicious activity.", "remediation": "Correlate with the investigation scope.", "evidence": e})
    return sorted(timeline, key=lambda r: r["timestamp"])

import argparse
import json
import sys
from pathlib import Path

def finding(resource, severity, check, detail, remediation, evidence):
    return dict(resource=resource, severity=severity, check=check, detail=detail, remediation=remediation, evidence=evidence)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--fail-on-high", action="store_true")
    args = p.parse_args()
    try:
        data = json.loads(args.input.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        results = analyze(data)
        text = json.dumps({"results": results, "count": len(results), "scope": __doc__}, indent=2)
        if args.output:
            args.output.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return int(args.fail_on_high and any(r["severity"] == "HIGH" for r in results))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
        print(f"Input/report error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())

