#!/usr/bin/env python3
"""
Replace MITRE ATT&CK technique/tactic IDs with their real names in camelCase.

Usage:
    python replace_mitre_ids.py <input_file> [output_file]

If output_file is omitted, result is printed to stdout.
The MITRE ATT&CK STIX data is cached at ~/.cache/mitre_attack.json.
"""

import re
import json
import sys
import urllib.request
from pathlib import Path

MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
CACHE_FILE = Path.home() / ".cache" / "mitre_attack.json"

# Matches T1234, T1234.001, TA0001 — not preceded by a letter/digit,
# not followed by a digit (so T1059 in T1059.001 is captured as T1059.001).
TECHNIQUE_RE = re.compile(r"(?<![A-Za-z\d])(?:T\d{4}(?:\.\d{3})?|TA\d{4})(?!\d)")


def to_camel_case(name: str) -> str:
    """Convert a MITRE name like 'Encrypted Channel: Asymmetric Cryptography'
    into camelCase: 'encryptedChannelAsymmetricCryptography'."""
    words = re.split(r"[\s\-/:.,()\[\]]+", name)
    words = [w for w in words if w]
    if not words:
        return name
    result = words[0][0].upper() + words[0][1:]
    for word in words[1:]:
        if word:
            result += word[0].upper() + word[1:]
    return result


def load_mitre_data() -> dict:
    """Return MITRE ATT&CK STIX bundle, downloading and caching if needed."""
    if CACHE_FILE.exists():
        print(f"[info] Using cached MITRE data from {CACHE_FILE}", file=sys.stderr)
        with open(CACHE_FILE) as f:
            return json.load(f)

    print(f"[info] Downloading MITRE ATT&CK data ...", file=sys.stderr)
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(MITRE_STIX_URL, CACHE_FILE)
    print(f"[info] Saved to {CACHE_FILE}", file=sys.stderr)
    with open(CACHE_FILE) as f:
        return json.load(f)


def build_id_map(stix_data: dict) -> dict[str, str]:
    """Build {technique_id: camelCaseName} from STIX objects."""
    id_to_name: dict[str, str] = {}

    for obj in stix_data.get("objects", []):
        obj_type = obj.get("type", "")

        if obj_type in ("attack-pattern", "x-mitre-tactic"):
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id", "")
                    name = obj.get("name", "")
                    if mitre_id and name:
                        id_to_name[mitre_id] = to_camel_case(name)

    return id_to_name


def replace_ids(text: str, id_to_name: dict[str, str]) -> str:
    """Replace every MITRE ID in *text* with its camelCase name."""

    def replacer(m: re.Match) -> str:
        mid = m.group(0)
        name = id_to_name.get(mid)
        return f"'{name}'" if name else mid  # leave unknown IDs untouched

    return TECHNIQUE_RE.sub(replacer, text)


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_file> [output_file]", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    stix_data = load_mitre_data()
    id_to_name = build_id_map(stix_data)
    print(f"[info] Loaded {len(id_to_name)} MITRE technique/tactic entries", file=sys.stderr)

    with open(input_path) as f:
        text = f.read()

    result = replace_ids(text, id_to_name)

    if output_path:
        with open(output_path, "w") as f:
            f.write(result)
        print(f"[info] Output written to {output_path}", file=sys.stderr)
    else:
        print(result)


if __name__ == "__main__":
    main()
