import json
import csv
from datetime import datetime

from . import display as _ui
from .utils import safe_name


def json_output(result, target, qtype):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"spyglass_{qtype}_{safe_name(target)}_{ts}.json"
    with open(path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    _ui.info(f"Saved {path}")
    return path


def csv_output(result, target, qtype):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"spyglass_{qtype}_{safe_name(target)}_{ts}.csv"
    flat = _flatten(result)
    if not flat:
        return
    # Flattening can yield rows with heterogeneous keys (a module result mixes
    # top-level scalars with nested dicts/lists). Union every key so DictWriter
    # gets a complete schema instead of crashing on the first row's subset.
    fieldnames = []
    for row in flat:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
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
            if isinstance(item, (dict, list)):
                subs = _flatten(item, f"{prefix}{i}_")
                if subs:
                    rows.extend(subs)
            else:
                # Scalar list item — keep the field's own name (e.g. subdomains),
                # don't collapse it into a generic "value" column.
                rows.append({prefix.rstrip("_"): str(item)})
    return rows if rows else [{"value": str(data)}]
