import hashlib
import json
import math
import re
import unicodedata
from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

SAFE_INT_MAX = (1 << 53) - 1

URI_RE = re.compile(r"^gs://[^/]+/[^/]+$")
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
# CRC32C - Castagnoli
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

def canonicalize(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    value = value.lower()
    return " ".join(value.split())


# ============================================================
# Timestamp validation / canonicalization
# ============================================================

def parse_timestamp(value: Any):
    if not isinstance(value, str):
        return None

    match = TIME_RE.fullmatch(value)

    if match is None:
        return None

    year = int(match.group(1))
    month = int(match.group(2))
    day = int(match.group(3))
    hour = int(match.group(4))
    minute = int(match.group(5))
    second = int(match.group(6))

    fraction = match.group(7) or ""
    offset = match.group(8)

    if offset == "Z":
        tz = timezone.utc
    else:
        sign = 1 if offset[0] == "+" else -1

        offset_hour = int(offset[1:3])
        offset_minute = int(offset[4:6])

        if offset_hour > 14:
            return None

        if offset_minute > 59:
            return None

        if offset_hour == 14 and offset_minute != 0:
            return None

        tz = timezone(
            sign * timedelta(
                hours=offset_hour,
                minutes=offset_minute
            )
        )

    milliseconds = int(fraction.ljust(3, "0")) if fraction else 0

    try:
        dt = datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            milliseconds * 1000,
            tzinfo=tz,
        )
    except ValueError:
        return None

    return dt.astimezone(timezone.utc)


def canonical_timestamp(value: str):
    dt = parse_timestamp(value)

    if dt is None:
        return None

    return (
        dt.strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{dt.microsecond // 1000:03d}Z"
    )


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

    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
    ):
        return False, None, None, None

    if not math.isfinite(float(threshold)):
        return False, None, None, None

    if not 0 <= float(threshold) <= 1:
        return False, None, None, None

    if min_time > max_time:
        return False, None, None, None

    return (
        True,
        min_time,
        max_time,
        float(threshold),
    )


# ============================================================
# Compact JSON
# ============================================================

def compact_json(value) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


# ============================================================
# JSONL parser
# ============================================================

def parse_jsonl(content: Any):
    """
    Returns:

        rows
        jsonl_invalid
        schema_invalid
    """

    if not isinstance(content, str):
        return [], False, True

    lines = [
        line
        for line in content.splitlines()
        if line.strip() != ""
    ]

    # Empty JSONL file
    if not lines:
        return [], False, True

    rows = []

    for line in lines:

        # JSON parsing error
        try:
            obj = json.loads(line)
        except Exception:
            return [], True, False

        # Every non-blank line must be an object
        if not isinstance(obj, dict):
            return [], False, True

        # Exact key set
        if set(obj.keys()) != ROW_KEYS:
            return [], False, True

        # Exact string fields
        if not isinstance(obj["id"], str):
            return [], False, True

        if not isinstance(obj["entity"], str):
            return [], False, True

        if not isinstance(obj["eventTime"], str):
            return [], False, True

        if not isinstance(obj["text"], str):
            return [], False, True

        # Revision must be non-negative safe integer
        revision = obj["revision"]

        if (
            isinstance(revision, bool)
            or not isinstance(revision, int)
            or revision < 0
            or revision > SAFE_INT_MAX
        ):
            return [], False, True

        # Event time must be valid
        event_time = parse_timestamp(obj["eventTime"])

        if event_time is None:
            return [], False, True

        rows.append(
            {
                "id": obj["id"],
                "entity": canonicalize(obj["entity"]),
                "eventTime": canonical_timestamp(
                    obj["eventTime"]
                ),
                "revision": revision,
                "text": canonicalize(obj["text"]),
            }
        )

    return rows, False, False


# ============================================================
# Word sets
# ============================================================

def unicode_word_set(value: str):
    result = []
    current = []

    for char in value.lower():

        category = unicodedata.category(char)

        if category.startswith("L") or category.startswith("N"):
            current.append(char)

        else:
            if current:
                result.append("".join(current))
                current = []

    if current:
        result.append("".join(current))

    return set(result)


def row_word_set(row):
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

    ordered = {
        "id": row["id"],
        "entity": row["entity"],
        "eventTime": row["eventTime"],
        "revision": row["revision"],
        "text": row["text"],
    }

    return compact_json(ordered)


def digest_rows(rows):

    data = b""

    for row in rows:
        data += serialize_row(row).encode("utf-8")
        data += b"\n"

    return hashlib.sha256(data).hexdigest()


# ============================================================
# Reason sorting
# ============================================================

def sort_reasons(reason_codes):

    return sorted(
        set(reason_codes),
        key=lambda value: value.encode("utf-8"),
    )


# ============================================================
# Object validation
# ============================================================

def validate_object(obj):

    reasons = []

    # --------------------------------------------------------
    # Object itself
    # --------------------------------------------------------

    if not isinstance(obj, dict):

        return (
            {
                "uri": None,
                "reasonCodes": ["SCHEMA_INVALID"],
            },
            [],
        )

    # --------------------------------------------------------
    # URI
    # --------------------------------------------------------

    uri = obj.get("uri")

    if (
        not isinstance(uri, str)
        or URI_RE.fullmatch(uri) is None
    ):
        reasons.append("URI_INVALID")

    # --------------------------------------------------------
    # Generation
    # --------------------------------------------------------

    generation = obj.get("generation")
    fetched_generation = obj.get("fetchedGeneration")

    generation_valid = (
        isinstance(generation, str)
        and GENERATION_RE.fullmatch(generation) is not None
    )

    fetched_generation_valid = (
        isinstance(fetched_generation, str)
        and GENERATION_RE.fullmatch(
            fetched_generation
        ) is not None
    )

    if (
        not generation_valid
        or not fetched_generation_valid
    ):
        reasons.append("GENERATION_INVALID")

    if (
        generation_valid
        and fetched_generation_valid
        and generation != fetched_generation
    ):
        reasons.append("GENERATION_MISMATCH")

    # --------------------------------------------------------
    # CRC32C
    # --------------------------------------------------------

    supplied_crc = obj.get("crc32c")

    crc_valid = (
        isinstance(supplied_crc, str)
        and CRC_RE.fullmatch(supplied_crc) is not None
    )

    if not crc_valid:
        reasons.append("CRC32C_INVALID")

    # --------------------------------------------------------
    # Schema / content
    # --------------------------------------------------------

    schema_id = obj.get("schemaId")
    content = obj.get("content")

    if schema_id != "training-v1":
        reasons.append("SCHEMA_INVALID")

    if not isinstance(content, str):
        reasons.append("SCHEMA_INVALID")

    # --------------------------------------------------------
    # CRC mismatch
    #
    # Only check mismatch when:
    #   - content is a string
    #   - CRC syntax is valid
    # --------------------------------------------------------

    if (
        isinstance(content, str)
        and crc_valid
    ):

        actual_crc = crc32c_hex(
            content.encode("utf-8")
        )

        if actual_crc != supplied_crc:
            reasons.append("CRC32C_MISMATCH")

    # --------------------------------------------------------
    # JSONL parsing
    #
    # This is deliberately independent from schemaId.
    # --------------------------------------------------------

    rows = []

    if isinstance(content, str):

        (
            rows,
            jsonl_invalid,
            schema_invalid,
        ) = parse_jsonl(content)

        if jsonl_invalid:
            reasons.append("JSONL_INVALID")

        if schema_invalid:
            reasons.append("SCHEMA_INVALID")

    # --------------------------------------------------------
    # Final object result
    # --------------------------------------------------------

    reasons = sort_reasons(reasons)

    if reasons:

        return (
            {
                "uri": (
                    uri
                    if isinstance(uri, str)
                    else None
                ),
                "reasonCodes": reasons,
            },
            [],
        )

    return None, rows


# ============================================================
# API
# ============================================================

@app.post("/build-corpus")
async def build_corpus(request: Request):

    # --------------------------------------------------------
    # Content-Type
    # --------------------------------------------------------

    content_type = request.headers.get(
        "content-type",
        "",
    )

    if not content_type.lower().startswith(
        "application/json"
    ):
        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    # --------------------------------------------------------
    # Request JSON
    # --------------------------------------------------------

    try:
        body = await request.json()

    except Exception:

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    # --------------------------------------------------------
    # Top-level request validation
    # --------------------------------------------------------

    if not isinstance(body, dict):

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    if "policy" not in body:

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    if "objects" not in body:

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    if not isinstance(body["objects"], list):

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    # --------------------------------------------------------
    # Policy
    # --------------------------------------------------------

    (
        policy_valid,
        min_time,
        max_time,
        contamination_threshold,
    ) = validate_policy(
        body["policy"]
    )

    rejected_objects = []
    rejected_rows = []
    lineage = []
    all_rows = []

    # --------------------------------------------------------
    # Objects
    # --------------------------------------------------------

    for obj in body["objects"]:

        rejection, rows = validate_object(obj)

        if rejection is not None:

            rejected_objects.append(
                rejection
            )

            continue

        lineage.append(
            {
                "uri": obj["uri"],
                "generation": obj["generation"],
                "crc32c": obj["crc32c"],
                "schemaId": obj["schemaId"],
            }
        )

        for row in rows:

            row["_source_uri"] = obj["uri"]

            all_rows.append(row)

    # ========================================================
    # Deduplication
    # ========================================================

    groups = {}

    for row in all_rows:

        key = (
            row["entity"],
            row["eventTime"],
            row["text"],
        )

        groups.setdefault(
            key,
            [],
        ).append(row)

    retained_rows = []

    for candidates in groups.values():

        candidates.sort(
            key=lambda row: (
                -row["revision"],
                row["id"].encode("utf-8"),
                serialize_row(row).encode("utf-8"),
            )
        )

        winner = candidates[0]

        retained_rows.append(winner)

        for loser in candidates[1:]:

            rejected_rows.append(
                {
                    "id": loser["id"],
                    "reasonCodes": [
                        "DUPLICATE"
                    ],
                }
            )

    # ========================================================
    # Policy + time window
    # ========================================================

    policy_rows = []

    for row in retained_rows:

        if not policy_valid:

            rejected_rows.append(
                {
                    "id": row["id"],
                    "reasonCodes": [
                        "POLICY_INVALID"
                    ],
                }
            )

            continue

        row_time = parse_timestamp(
            row["eventTime"]
        )

        if (
            row_time < min_time
            or row_time > max_time
        ):

            rejected_rows.append(
                {
                    "id": row["id"],
                    "reasonCodes": [
                        "OUT_OF_WINDOW"
                    ],
                }
            )

            continue

        policy_rows.append(row)

    # ========================================================
    # Deterministic split
    # ========================================================

    splits = {
        "train": [],
        "validation": [],
        "test": [],
    }

    for row in policy_rows:

        entity_hash = hashlib.sha256(
            row["entity"].encode("utf-8")
        ).digest()

        bucket = entity_hash[0] % 10

        if bucket <= 5:
            split = "train"

        elif bucket <= 7:
            split = "validation"

        else:
            split = "test"

        splits[split].append(row)

    # ========================================================
    # Contamination
    # ========================================================

    train_sets = [
        row_word_set(row)
        for row in splits["train"]
    ]

    for split_name in (
        "validation",
        "test",
    ):

        kept = []

        for row in splits[split_name]:

            row_words = row_word_set(row)

            contaminated = False

            for train_words in train_sets:

                similarity = jaccard(
                    row_words,
                    train_words,
                )

                if (
                    similarity
                    >= contamination_threshold
                ):

                    contaminated = True
                    break

            if contaminated:

                rejected_rows.append(
                    {
                        "id": row["id"],
                        "reasonCodes": [
                            "TRAIN_CONTAMINATION"
                        ],
                    }
                )

            else:

                kept.append(row)

        splits[split_name] = kept

    # ========================================================
    # Remove internal fields
    # ========================================================

    for split_name in splits:

        for row in splits[split_name]:

            row.pop("_source_uri", None)

    # ========================================================
    # Sort split rows
    # ========================================================

    for split_name in splits:

        splits[split_name].sort(
            key=lambda row: (
                row["id"].encode("utf-8"),
                serialize_row(row).encode("utf-8"),
            )
        )

    # ========================================================
    # Merge rejected rows with same ID
    # ========================================================

    rejected_row_map = {}

    for item in rejected_rows:

        row_id = item["id"]

        if row_id not in rejected_row_map:

            rejected_row_map[row_id] = set()

        rejected_row_map[row_id].update(
            item["reasonCodes"]
        )

    rejected_rows = []

    for row_id, reason_set in rejected_row_map.items():

        rejected_rows.append(
            {
                "id": row_id,
                "reasonCodes": sort_reasons(
                    reason_set
                ),
            }
        )

    rejected_rows.sort(
        key=lambda item: (
            item["id"].encode("utf-8"),
            compact_json(item).encode("utf-8"),
        )
    )

    # ========================================================
    # Sort rejected objects
    # ========================================================

    for item in rejected_objects:

        item["reasonCodes"] = sort_reasons(
            item["reasonCodes"]
        )

    rejected_objects.sort(
        key=lambda item: (
            (
                item["uri"].encode("utf-8")
                if isinstance(item["uri"], str)
                else b""
            ),
            compact_json(item).encode("utf-8"),
        )
    )

    # ========================================================
    # Sort lineage
    # ========================================================

    lineage.sort(
        key=lambda item: (
            item["uri"].encode("utf-8"),
            compact_json(item).encode("utf-8"),
        )
    )

    # ========================================================
    # Digests
    # ========================================================

    digests = {
        "train": digest_rows(
            splits["train"]
        ),
        "validation": digest_rows(
            splits["validation"]
        ),
        "test": digest_rows(
            splits["test"]
        ),
    }

    # ========================================================
    # Exact response shape
    # ========================================================

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
    return {
        "status": "ok"
    }