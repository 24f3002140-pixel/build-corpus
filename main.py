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

# gs://bucket/object
# Object names may themselves contain '/'.
URI_RE = re.compile(r"^gs://[^/]+/.+$")

GENERATION_RE = re.compile(r"^[0-9]+$")
CRC_RE = re.compile(r"^[0-9a-f]{8}$")

TIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T"
    r"(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,3}))?"
    r"(Z|[+-]\d{2}:\d{2})$"
)

ROW_KEYS = {
    "id",
    "entity",
    "eventTime",
    "revision",
    "text",
}


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

def canonicalize(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    value = value.lower()
    value = " ".join(value.split())
    return value


# ============================================================
# Timestamp parsing
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

    # Validate offset.
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
            sign
            * timedelta(
                hours=offset_hour,
                minutes=offset_minute,
            )
        )

    milliseconds = 0

    if fraction:
        milliseconds = int(
            fraction.ljust(3, "0")
        )

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
# Policy
# ============================================================

def validate_policy(policy: Any):

    if not isinstance(policy, dict):
        return False, None, None, None

    min_time = parse_timestamp(
        policy.get("minTime")
    )

    max_time = parse_timestamp(
        policy.get("maxTime")
    )

    threshold = policy.get(
        "contaminationThreshold"
    )

    if min_time is None:
        return False, None, None, None

    if max_time is None:
        return False, None, None, None

    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
    ):
        return False, None, None, None

    if not math.isfinite(
        float(threshold)
    ):
        return False, None, None, None

    if not (
        0 <= float(threshold) <= 1
    ):
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
# JSON serialization
# ============================================================

def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def utf8(value):
    return value.encode("utf-8")


# ============================================================
# JSONL validation
# ============================================================

def parse_jsonl(content):

    if not isinstance(content, str):
        return [], False, True

    # JSONL uses LF / CRLF line boundaries.
    lines = content.split("\n")

    nonblank = []

    for line in lines:

        if line.endswith("\r"):
            line = line[:-1]

        if line.strip() == "":
            continue

        nonblank.append(line)

    # Empty file
    if not nonblank:
        return [], False, True

    rows = []

    for line in nonblank:

        # JSON syntax
        try:
            obj = json.loads(line)
        except Exception:
            return [], True, False

        # Every parsed line must be an object.
        if not isinstance(obj, dict):
            return [], False, True

        # Exactly these keys.
        if set(obj.keys()) != ROW_KEYS:
            return [], False, True

        # Four string fields.
        if not isinstance(obj["id"], str):
            return [], False, True

        if not isinstance(obj["entity"], str):
            return [], False, True

        if not isinstance(obj["eventTime"], str):
            return [], False, True

        if not isinstance(obj["text"], str):
            return [], False, True

        # Revision = non-negative safe integer.
        revision = obj["revision"]

        if isinstance(revision, bool):
            return [], False, True

        if not isinstance(revision, int):
            return [], False, True

        if revision < 0:
            return [], False, True

        if revision > SAFE_INT_MAX:
            return [], False, True

        # Event time must be valid.
        if parse_timestamp(
            obj["eventTime"]
        ) is None:
            return [], False, True

        rows.append(
            {
                "id": obj["id"],
                "entity": canonicalize(
                    obj["entity"]
                ),
                "eventTime": canonical_timestamp(
                    obj["eventTime"]
                ),
                "revision": revision,
                "text": canonicalize(
                    obj["text"]
                ),
            }
        )

    return rows, False, False


# ============================================================
# Object validation
# ============================================================

def validate_object(obj):

    # A non-object itself can only produce SCHEMA_INVALID.
    if not isinstance(obj, dict):

        return (
            {
                "uri": None,
                "reasonCodes": [
                    "SCHEMA_INVALID"
                ],
            },
            [],
        )

    reasons = []

    # --------------------------------------------------------
    # URI
    # --------------------------------------------------------

    uri = obj.get("uri")

    if (
        not isinstance(uri, str)
        or URI_RE.fullmatch(uri) is None
    ):
        reasons.append(
            "URI_INVALID"
        )

    # --------------------------------------------------------
    # Generation
    # --------------------------------------------------------

    generation = obj.get(
        "generation"
    )

    fetched_generation = obj.get(
        "fetchedGeneration"
    )

    generation_valid = (
        isinstance(generation, str)
        and GENERATION_RE.fullmatch(
            generation
        ) is not None
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
        reasons.append(
            "GENERATION_INVALID"
        )

    if (
        generation_valid
        and fetched_generation_valid
        and generation != fetched_generation
    ):
        reasons.append(
            "GENERATION_MISMATCH"
        )

    # --------------------------------------------------------
    # CRC32C
    # --------------------------------------------------------

    supplied_crc = obj.get(
        "crc32c"
    )

    crc_valid = (
        isinstance(supplied_crc, str)
        and CRC_RE.fullmatch(
            supplied_crc
        ) is not None
    )

    if not crc_valid:
        reasons.append(
            "CRC32C_INVALID"
        )

    # --------------------------------------------------------
    # Schema ID
    # --------------------------------------------------------

    schema_id = obj.get(
        "schemaId"
    )

    if schema_id != "training-v1":
        reasons.append(
            "SCHEMA_INVALID"
        )

    # --------------------------------------------------------
    # Content
    # --------------------------------------------------------

    content = obj.get(
        "content"
    )

    if not isinstance(content, str):
        reasons.append(
            "SCHEMA_INVALID"
        )

    # --------------------------------------------------------
    # CRC mismatch
    #
    # Only check when content is a string and
    # CRC syntax is valid.
    # --------------------------------------------------------

    if (
        isinstance(content, str)
        and crc_valid
    ):

        actual_crc = crc32c_hex(
            content.encode("utf-8")
        )

        if actual_crc != supplied_crc:
            reasons.append(
                "CRC32C_MISMATCH"
            )

    # --------------------------------------------------------
    # JSONL
    #
    # Parsing is independent of schemaId.
    # --------------------------------------------------------

    rows = []

    if isinstance(content, str):

        (
            parsed_rows,
            jsonl_invalid,
            schema_invalid,
        ) = parse_jsonl(content)

        rows = parsed_rows

        if jsonl_invalid:
            reasons.append(
                "JSONL_INVALID"
            )

        if schema_invalid:
            reasons.append(
                "SCHEMA_INVALID"
            )

    # --------------------------------------------------------
    # Object rejection
    # --------------------------------------------------------

    reasons = sorted(
        set(reasons),
        key=lambda x: x.encode("utf-8"),
    )

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
# Row serialization
# ============================================================

def serialize_row(row):

    return compact_json(
        {
            "id": row["id"],
            "entity": row["entity"],
            "eventTime": row["eventTime"],
            "revision": row["revision"],
            "text": row["text"],
        }
    )


def digest_rows(rows):

    data = bytearray()

    for row in rows:

        data.extend(
            serialize_row(row).encode("utf-8")
        )

        data.extend(b"\n")

    return hashlib.sha256(
        bytes(data)
    ).hexdigest()


# ============================================================
# Contamination
# ============================================================

def unicode_word_set(value):

    result = []
    current = []

    for char in value.lower():

        category = unicodedata.category(
            char
        )

        if (
            category.startswith("L")
            or category.startswith("N")
        ):
            current.append(char)

        else:

            if current:
                result.append(
                    "".join(current)
                )

                current = []

    if current:
        result.append(
            "".join(current)
        )

    return set(result)


def row_word_set(row):

    return unicode_word_set(
        row["entity"]
        + " "
        + row["text"]
    )


def jaccard(a, b):

    if not a and not b:
        return 1.0

    union = a | b

    if not union:
        return 1.0

    return len(a & b) / len(union)


# ============================================================
# Endpoint
# ============================================================

@app.post("/build-corpus")
async def build_corpus(
    request: Request
):

    # --------------------------------------------------------
    # Request Content-Type
    # --------------------------------------------------------

    content_type = request.headers.get(
        "content-type",
        ""
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
    # Parse request JSON
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
    # Top-level request
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

    if not isinstance(
        body["objects"],
        list
    ):

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

    # ========================================================
    # Objects
    # ========================================================

    for obj in body["objects"]:

        rejection, rows = validate_object(
            obj
        )

        if rejection is not None:

            rejected_objects.append(
                rejection
            )

            continue

        # Valid object contributes lineage.
        lineage.append(
            {
                "uri": obj["uri"],
                "generation": obj[
                    "generation"
                ],
                "crc32c": obj[
                    "crc32c"
                ],
                "schemaId": obj[
                    "schemaId"
                ],
            }
        )

        for row in rows:

            row["_source_uri"] = obj[
                "uri"
            ]

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

        if key not in groups:
            groups[key] = []

        groups[key].append(row)

    retained_rows = []

    for candidates in groups.values():

        candidates.sort(
            key=lambda row: (
                -row["revision"],
                utf8(row["id"]),
                utf8(
                    serialize_row(row)
                ),
            )
        )

        winner = candidates[0]

        retained_rows.append(
            winner
        )

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
    # Policy / window
    # ========================================================

    filtered_rows = []

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

        filtered_rows.append(row)

    # ========================================================
    # Split
    # ========================================================

    splits = {
        "train": [],
        "validation": [],
        "test": [],
    }

    for row in filtered_rows:

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

        splits[split].append(row)

    # ========================================================
    # Train contamination
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

            row_words = row_word_set(
                row
            )

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

            row.pop(
                "_source_uri",
                None
            )

    # ========================================================
    # Sort split rows
    # ========================================================

    for split_name in splits:

        splits[split_name].sort(
            key=lambda row: (
                utf8(row["id"]),
                utf8(
                    serialize_row(row)
                ),
            )
        )

    # ========================================================
    # Merge rejected rows
    # ========================================================

    rejected_map = {}

    for item in rejected_rows:

        row_id = item["id"]

        if row_id not in rejected_map:
            rejected_map[row_id] = set()

        rejected_map[row_id].update(
            item["reasonCodes"]
        )

    rejected_rows = []

    for row_id, code_set in (
        rejected_map.items()
    ):

        rejected_rows.append(
            {
                "id": row_id,
                "reasonCodes": sort_reasons(
                    code_set
                ),
            }
        )

    rejected_rows.sort(
        key=lambda item: (
            utf8(item["id"]),
            utf8(
                compact_json(item)
            ),
        )
    )

    # ========================================================
    # Rejected objects
    # ========================================================

    for item in rejected_objects:

        item["reasonCodes"] = sort_reasons(
            item["reasonCodes"]
        )

    rejected_objects.sort(
        key=lambda item: (
            (
                utf8(item["uri"])
                if isinstance(
                    item["uri"],
                    str
                )
                else b""
            ),
            utf8(
                compact_json(item)
            ),
        )
    )

    # ========================================================
    # Lineage
    # ========================================================

    lineage.sort(
        key=lambda item: (
            utf8(item["uri"]),
            utf8(
                compact_json(item)
            ),
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
    # Exact response
    # ========================================================

    return {
        "splits": {
            "train": splits["train"],
            "validation": splits[
                "validation"
            ],
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