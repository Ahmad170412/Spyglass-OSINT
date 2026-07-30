import json
import csv
from datetime import datetime

from . import display as _ui


def json_output(result, target, qtype):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"spyglass_{qtype}_{target}_{ts}.json"
    with open(path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    _ui.info(f"Saved {path}")
    return path


def csv_output(result, target, qtype):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"spyglass_{qtype}_{target}_{ts}.csv"
    flat = _flatten(result)
    if not flat:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(flat[0].keys()))
        w.writeheader()
        w.writerows(flat)
    _ui.info(f"Saved {path}")
    return path


def _flatten(data, prefix=""):
    rows = []
    if isinstance(data, dict):
        row = {}
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                subs = _flatten(v, f"{prefix}{k}_")
                if subs:
                    rows.extend(subs)
                else:
                    row[f"{prefix}{k}"] = str(v) if not isinstance(v, (int, float, bool)) else v
            else:
                row[f"{prefix}{k}"] = str(v) if not isinstance(v, (int, float, bool)) else v
        if row:
            rows.append(row)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            subs = _flatten(item, f"{prefix}{i}_")
            if subs:
                rows.extend(subs)
            else:
                rows.append({prefix.rstrip("_"): str(item)})
    return rows if rows else [{"value": str(data)}]
