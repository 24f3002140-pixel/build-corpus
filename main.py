import hashlib
import json
import math
import re
from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()


# ============================================================
# Constants / regex
# ============================================================

SAFE_INT_MAX = (1 << 53) - 1

URI_RE = re.compile(r"^gs://[^/]+/.+$")
GENERATION_RE = re.compile(r"^[0-9]+$")
CRC_RE = re.compile(r"^[0-9a-f]{8}$")

TIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T"
    r"(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,3}))?"
    r"(Z|[+-]\d{2}:\d{2})$"
)

ROW_KEYS = {"id", "entity", "eventTime", "revision", "text"}


# ============================================================
# CRC32C Castagnoli
# ============================================================

CRC32C_TABLE = []

for i in range(256):
    crc = i
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0x82F63B78
        else:
            crc >>= 1
    CRC32C_TABLE.append(crc)


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF

    for byte in data:
        crc = CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)

    return crc ^ 0xFFFFFFFF


def crc32c_hex(data: bytes) -> str:
    return f"{crc32c(data):08x}"


# ============================================================
# Unicode canonicalization
# ============================================================

def canonicalize_text(value: str) -> str:
    value = value.encode("utf-8").decode("utf-8")
    value = __import__("unicodedata").normalize("NFKC", value)
    value = value.lower()

    # Unicode whitespace -> one ASCII space
    parts = value.split()
    return " ".join(parts)


# ============================================================
# Timestamp parsing
# ============================================================

def parse_timestamp(value: Any):
    if not isinstance(value, str):
        return None

    m = TIME_RE.fullmatch(value)

    if not m:
        return None

    year = int(m.group(1))
    month = int(m.group(2))
    day = int(m.group(3))
    hour = int(m.group(4))
    minute = int(m.group(5))
    second = int(m.group(6))
    fraction = m.group(7) or ""
    offset = m.group(8)

    # Offset validity
    if offset != "Z":
        sign = 1 if offset[0] == "+" else -1
        off_hour = int(offset[1:3])
        off_minute = int(offset[4:6])

        if off_hour > 14:
            return None

        if off_minute > 59:
            return None

        if off_hour == 14 and off_minute != 0:
            return None

        tz = timezone(
            sign * timedelta(hours=off_hour, minutes=off_minute)
        )
    else:
        tz = timezone.utc

    # Milliseconds
    if fraction:
        millis = int(fraction.ljust(3, "0"))
    else:
        millis = 0

    try:
        dt = datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            millis * 1000,
            tzinfo=tz,
        )
    except ValueError:
        return None

    return dt.astimezone(timezone.utc)


def canonical_timestamp(value: str):
    dt = parse_timestamp(value)

    if dt is None:
        return None

    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{dt.microsecond // 1000:03d}Z"


# ============================================================
# Policy validation
# ============================================================

def validate_policy(policy: Any):
    if not isinstance(policy, dict):
        return False, None, None, None

    min_time = parse_timestamp(policy.get("minTime"))
    max_time = parse_timestamp(policy.get("maxTime"))

    threshold = policy.get("contaminationThreshold")

    if min_time is None or max_time is None:
        return False, None, None, None

    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
        return False, None, None, None

    if not math.isfinite(float(threshold)):
        return False, None, None, None

    if not (0 <= float(threshold) <= 1):
        return False, None, None, None

    if min_time > max_time:
        return False, None, None, None

    return True, min_time, max_time, float(threshold)


# ============================================================
# JSON serialization
# ============================================================

def compact_json(value) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def utf8_key(value: str):
    return value.encode("utf-8")


# ============================================================
# Row validation
# ============================================================

def parse_jsonl(content: Any):
    """
    Returns:
        rows, object_has_jsonl_error, object_has_schema_error
    """

    if not isinstance(content, str):
        return [], False, True

    lines = content.splitlines()

    nonblank = [line for line in lines if line.strip() != ""]

    if not nonblank:
        return [], False, True

    rows = []

    for line in nonblank:
        try:
            obj = json.loads(line)
        except Exception:
            return [], True, False

        if not isinstance(obj, dict):
            return [], False, True

        if set(obj.keys()) != ROW_KEYS:
            return [], False, True

        if not isinstance(obj["id"], str):
            return [], False, True

        if not isinstance(obj["entity"], str):
            return [], False, True

        if not isinstance(obj["eventTime"], str):
            return [], False, True

        if not isinstance(obj["text"], str):
            return [], False, True

        revision = obj["revision"]

        if (
            isinstance(revision, bool)
            or not isinstance(revision, int)
            or revision < 0
            or revision > SAFE_INT_MAX
        ):
            return [], False, True

        parsed_time = parse_timestamp(obj["eventTime"])

        if parsed_time is None:
            return [], False, True

        rows.append(
            {
                "id": obj["id"],
                "entity": canonicalize_text(obj["entity"]),
                "eventTime": canonical_timestamp(obj["eventTime"]),
                "revision": revision,
                "text": canonicalize_text(obj["text"]),
            }
        )

    return rows, False, False


# ============================================================
# Word sets for contamination
# ============================================================

def unicode_word_set(value: str):
    """
    Extract runs consisting of Unicode letters/numbers.
    Lowercase canonicalized text is already supplied.
    """

    import unicodedata

    words = []
    current = []

    for ch in value.lower():
        category = unicodedata.category(ch)

        if category.startswith("L") or category.startswith("N"):
            current.append(ch)
        else:
            if current:
                words.append("".join(current))
                current = []

    if current:
        words.append("".join(current))

    return set(words)


def row_word_set(row):
    # The row's textual content is represented by entity + text.
    return unicode_word_set(
        row["entity"] + " " + row["text"]
    )


def jaccard(a, b):
    if not a and not b:
        return 1.0

    union = a | b

    if not union:
        return 1.0

    return len(a & b) / len(union)


# ============================================================
# Deterministic row serialization
# ============================================================

def serialize_row(row):
    # Exact key order required by the specification.
    ordered = {
        "id": row["id"],
        "entity": row["entity"],
        "eventTime": row["eventTime"],
        "revision": row["revision"],
        "text": row["text"],
    }

    return compact_json(ordered)


def digest_rows(rows):
    data = b"".join(
        serialize_row(row).encode("utf-8") + b"\n"
        for row in rows
    )

    return hashlib.sha256(data).hexdigest()


# ============================================================
# Rejection helpers
# ============================================================

def add_reason(target, reason):
    if reason not in target:
        target.append(reason)


def sort_reasons(reasons):
    return sorted(
        set(reasons),
        key=lambda x: x.encode("utf-8")
    )


def make_rejected_row(row_id, reasons):
    return {
        "id": row_id,
        "reasonCodes": sort_reasons(reasons),
    }


# ============================================================
# Object processing
# ============================================================

def process_object(obj):
    """
    Returns:
        object_rejection_or_None,
        parsed_rows
    """

    reasons = []

    uri = obj.get("uri") if isinstance(obj, dict) else None

    # URI
    if not isinstance(uri, str) or URI_RE.fullmatch(uri) is None:
        reasons.append("URI_INVALID")

    # Generations
    generation = obj.get("generation") if isinstance(obj, dict) else None
    fetched_generation = (
        obj.get("fetchedGeneration")
        if isinstance(obj, dict)
        else None
    )

    generation_valid = (
        isinstance(generation, str)
        and GENERATION_RE.fullmatch(generation) is not None
    )

    fetched_generation_valid = (
        isinstance(fetched_generation, str)
        and GENERATION_RE.fullmatch(fetched_generation) is not None
    )

    if not generation_valid or not fetched_generation_valid:
        reasons.append("GENERATION_INVALID")

    if (
        generation_valid
        and fetched_generation_valid
        and generation != fetched_generation
    ):
        reasons.append("GENERATION_MISMATCH")

    # CRC syntax
    supplied_crc = obj.get("crc32c") if isinstance(obj, dict) else None

    crc_valid = (
        isinstance(supplied_crc, str)
        and CRC_RE.fullmatch(supplied_crc) is not None
    )

    if not crc_valid:
        reasons.append("CRC32C_INVALID")

    # Schema
    schema_id = obj.get("schemaId") if isinstance(obj, dict) else None
    content = obj.get("content") if isinstance(obj, dict) else None

    schema_valid = (
        schema_id == "training-v1"
        and isinstance(content, str)
    )

    if not schema_valid:
        reasons.append("SCHEMA_INVALID")

    # CRC mismatch only for string content + valid syntax
    if (
        isinstance(content, str)
        and crc_valid
    ):
        actual_crc = crc32c_hex(content.encode("utf-8"))

        if actual_crc != supplied_crc:
            reasons.append("CRC32C_MISMATCH")

    # JSONL parsing
    rows = []

    if schema_valid:
        rows, jsonl_invalid, schema_row_invalid = parse_jsonl(content)

        if jsonl_invalid:
            reasons.append("JSONL_INVALID")

        if schema_row_invalid:
            reasons.append("SCHEMA_INVALID")

    reasons = sort_reasons(reasons)

    if reasons:
        return (
            {
                "uri": uri if isinstance(uri, str) else None,
                "reasonCodes": reasons,
            },
            []
        )

    return None, rows


# ============================================================
# Main endpoint
# ============================================================

@app.post("/build-corpus")
async def build_corpus(request: Request):

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"},
        )

    if (
        not isinstance(body, dict)
        or "policy" not in body
        or "objects" not in body
        or not isinstance(body["objects"], list)
    ):
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"},
        )

    policy = body["policy"]
    objects = body["objects"]

    policy_valid, min_time, max_time, threshold = validate_policy(
        policy
    )

    rejected_objects = []
    all_rows = []

    lineage = []

    # --------------------------------------------------------
    # Validate objects
    # --------------------------------------------------------

    for raw_obj in objects:

        if not isinstance(raw_obj, dict):
            rejected_objects.append(
                {
                    "uri": None,
                    "reasonCodes": ["SCHEMA_INVALID"],
                }
            )
            continue

        rejection, rows = process_object(raw_obj)

        if rejection is not None:
            rejected_objects.append(rejection)
            continue

        # Object is valid enough to contribute lineage.
        lineage.append(
            {
                "uri": raw_obj["uri"],
                "generation": raw_obj["generation"],
                "crc32c": raw_obj["crc32c"],
                "schemaId": raw_obj["schemaId"],
            }
        )

        for row in rows:
            row["_source_uri"] = raw_obj["uri"]
            all_rows.append(row)

    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------

    grouped = {}

    for row in all_rows:
        key = (
            row["entity"],
            row["eventTime"],
            row["text"],
        )

        grouped.setdefault(key, []).append(row)

    retained = []
    rejected_rows = []

    for _, candidates in grouped.items():

        candidates.sort(
            key=lambda r: (
                -r["revision"],
                utf8_key(r["id"]),
                utf8_key(serialize_row(r)),
            )
        )

        winner = candidates[0]
        retained.append(winner)

        for loser in candidates[1:]:
            rejected_rows.append(
                make_rejected_row(
                    loser["id"],
                    ["DUPLICATE"],
                )
            )

    # --------------------------------------------------------
    # Policy + time window
    # --------------------------------------------------------

    policy_filtered = []

    for row in retained:

        if not policy_valid:
            rejected_rows.append(
                make_rejected_row(
                    row["id"],
                    ["POLICY_INVALID"],
                )
            )
            continue

        row_time = parse_timestamp(row["eventTime"])

        if row_time < min_time or row_time > max_time:
            rejected_rows.append(
                make_rejected_row(
                    row["id"],
                    ["OUT_OF_WINDOW"],
                )
            )
            continue

        policy_filtered.append(row)

    # --------------------------------------------------------
    # Deterministic bucket split
    # --------------------------------------------------------

    splits = {
        "train": [],
        "validation": [],
        "test": [],
    }

    for row in policy_filtered:

        digest = hashlib.sha256(
            row["entity"].encode("utf-8")
        ).digest()

        bucket = digest[0] % 10

        if bucket <= 5:
            split = "train"
        elif bucket <= 7:
            split = "validation"
        else:
            split = "test"

        row["_split"] = split
        splits[split].append(row)

    # --------------------------------------------------------
    # Train contamination
    # --------------------------------------------------------

    train_word_sets = [
        row_word_set(row)
        for row in splits["train"]
    ]

    for split_name in ("validation", "test"):

        kept = []

        for row in splits[split_name]:

            words = row_word_set(row)

            contaminated = False

            for train_words in train_word_sets:
                if jaccard(words, train_words) >= threshold:
                    contaminated = True
                    break

            if contaminated:
                rejected_rows.append(
                    make_rejected_row(
                        row["id"],
                        ["TRAIN_CONTAMINATION"],
                    )
                )
            else:
                kept.append(row)

        splits[split_name] = kept

    # --------------------------------------------------------
    # Remove internal fields
    # --------------------------------------------------------

    for split_name in splits:
        for row in splits[split_name]:
            row.pop("_source_uri", None)
            row.pop("_split", None)

    # --------------------------------------------------------
    # Sort split rows
    # --------------------------------------------------------

    for split_name in splits:
        splits[split_name].sort(
            key=lambda row: (
                utf8_key(row["id"]),
                utf8_key(serialize_row(row)),
            )
        )

    # --------------------------------------------------------
    # Sort rejected rows
    # --------------------------------------------------------

    # Merge identical rejected-row IDs/reasons.
    rejected_map = {}

    for item in rejected_rows:

        row_id = item["id"]

        if row_id not in rejected_map:
            rejected_map[row_id] = set()

        rejected_map[row_id].update(item["reasonCodes"])

    rejected_rows = [
        {
            "id": row_id,
            "reasonCodes": sort_reasons(
                list(reasons)
            ),
        }
        for row_id, reasons in rejected_map.items()
    ]

    rejected_rows.sort(
        key=lambda item: (
            utf8_key(item["id"]),
            utf8_key(compact_json(item)),
        )
    )

    # --------------------------------------------------------
    # Sort rejected objects
    # --------------------------------------------------------

    for item in rejected_objects:
        item["reasonCodes"] = sort_reasons(
            item["reasonCodes"]
        )

    rejected_objects.sort(
        key=lambda item: (
            utf8_key(item["uri"]) if isinstance(item["uri"], str)
            else b"",
            utf8_key(compact_json(item)),
        )
    )

    # --------------------------------------------------------
    # Sort lineage
    # --------------------------------------------------------

    lineage.sort(
        key=lambda item: (
            utf8_key(item["uri"]),
            utf8_key(compact_json(item)),
        )
    )

    # --------------------------------------------------------
    # Digests
    # --------------------------------------------------------

    digests = {
        "train": digest_rows(splits["train"]),
        "validation": digest_rows(splits["validation"]),
        "test": digest_rows(splits["test"]),
    }

    # --------------------------------------------------------
    # Exact response shape
    # --------------------------------------------------------

    return {
        "splits": {
            "train": splits["train"],
            "validation": splits["validation"],
            "test": splits["test"],
        },
        "rejectedObjects": rejected_objects,
        "rejectedRows": rejected_rows,
        "digests": digests,
        "lineage": lineage,
    }


@app.get("/")
def root():
    return {"status": "ok"}