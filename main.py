import hashlib
import json
import math
import re
import unicodedata
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

SAFE_INT_MAX = 9007199254740991

GEN_RE = re.compile(r"^[0-9]+$")
CRC_RE = re.compile(r"^[0-9a-f]{8}$")

TIME_RE = re.compile(
    r"^"
    r"(\d{4})-(\d{2})-(\d{2})"
    r"T"
    r"(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,3}))?"
    r"(Z|[+-]\d{2}:\d{2})"
    r"$"
)

ROW_KEYS = {"id", "entity", "eventTime", "revision", "text"}


def utf8(value):
    return value.encode("utf-8")


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def reason_sort(values):
    return sorted(
        set(values),
        key=utf8,
    )


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


def crc32c(data):
    crc = 0xFFFFFFFF

    for byte in data:
        crc = (
            CRC32C_TABLE[(crc ^ byte) & 0xFF]
            ^ (crc >> 8)
        )

    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


def crc32c_hex(data):
    return f"{crc32c(data):08x}"


# ============================================================
# URI
# ============================================================

URI_RE = re.compile(
    r"^gs://([^/]+)/(.+)$"
)


def valid_uri(value):
    if not isinstance(value, str):
        return False

    match = URI_RE.fullmatch(value)

    if match is None:
        return False

    bucket = match.group(1)
    obj = match.group(2)

    return bool(bucket and obj)


# ============================================================
# TIME
# ============================================================

def parse_time(value):
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
    zone = match.group(8)

    if zone == "Z":
        tz = timezone.utc
    else:
        offset_hour = int(zone[1:3])
        offset_minute = int(zone[4:6])

        if offset_hour > 14:
            return None

        if offset_minute > 59:
            return None

        if offset_hour == 14 and offset_minute != 0:
            return None

        sign = 1 if zone[0] == "+" else -1

        tz = timezone(
            sign * timedelta(
                hours=offset_hour,
                minutes=offset_minute,
            )
        )

    milliseconds = int(
        fraction.ljust(3, "0")
    ) if fraction else 0

    try:
        dt = datetime(
            year=year,
            month=month,
            day=day,
            hour=hour,
            minute=minute,
            second=second,
            microsecond=milliseconds * 1000,
            tzinfo=tz,
        )
    except ValueError:
        return None

    return dt.astimezone(timezone.utc)


def canonical_time(value):
    dt = parse_time(value)

    if dt is None:
        return None

    return (
        dt.strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{dt.microsecond // 1000:03d}Z"
    )


# ============================================================
# TEXT CANONICALIZATION
# ============================================================

def canonical_text(value):
    value = unicodedata.normalize(
        "NFKC",
        value,
    )

    value = value.lower()

    # Unicode whitespace -> ASCII space,
    # collapse consecutive whitespace,
    # trim.
    return " ".join(value.split())


# ============================================================
# POLICY
# ============================================================

def validate_policy(policy):
    if not isinstance(policy, dict):
        return False, None, None, None

    min_time = parse_time(
        policy.get("minTime")
    )

    max_time = parse_time(
        policy.get("maxTime")
    )

    threshold = policy.get(
        "contaminationThreshold"
    )

    if min_time is None or max_time is None:
        return False, None, None, None

    if isinstance(threshold, bool):
        return False, None, None, None

    if not isinstance(
        threshold,
        (int, float),
    ):
        return False, None, None, None

    threshold = float(threshold)

    if not math.isfinite(threshold):
        return False, None, None, None

    if threshold < 0 or threshold > 1:
        return False, None, None, None

    if min_time > max_time:
        return False, None, None, None

    return (
        True,
        min_time,
        max_time,
        threshold,
    )


# ============================================================
# JSONL
# ============================================================

def parse_jsonl(content):
    if not isinstance(content, str):
        return None, "SCHEMA_INVALID"

    rows = []

    # JSONL is LF-delimited.
    # CRLF is accepted.
    for line in content.split("\n"):

        if line.endswith("\r"):
            line = line[:-1]

        if line.strip() == "":
            continue

        try:
            value = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, "JSONL_INVALID"

        if not isinstance(value, dict):
            return None, "SCHEMA_INVALID"

        if set(value.keys()) != ROW_KEYS:
            return None, "SCHEMA_INVALID"

        if not isinstance(value["id"], str):
            return None, "SCHEMA_INVALID"

        if not isinstance(value["entity"], str):
            return None, "SCHEMA_INVALID"

        if not isinstance(value["eventTime"], str):
            return None, "SCHEMA_INVALID"

        if not isinstance(value["text"], str):
            return None, "SCHEMA_INVALID"

        revision = value["revision"]

        if isinstance(revision, bool):
            return None, "SCHEMA_INVALID"

        if not isinstance(revision, int):
            return None, "SCHEMA_INVALID"

        if revision < 0:
            return None, "SCHEMA_INVALID"

        if revision > SAFE_INT_MAX:
            return None, "SCHEMA_INVALID"

        event_time = canonical_time(
            value["eventTime"]
        )

        if event_time is None:
            return None, "SCHEMA_INVALID"

        rows.append(
            {
                "id": value["id"],
                "entity": canonical_text(
                    value["entity"]
                ),
                "eventTime": event_time,
                "revision": revision,
                "text": canonical_text(
                    value["text"]
                ),
            }
        )

    if not rows:
        return None, "SCHEMA_INVALID"

    return rows, None


# ============================================================
# OBJECT VALIDATION
# ============================================================

def inspect_object(obj):
    reasons = []

    if not isinstance(obj, dict):
        return (
            {
                "uri": None,
                "reasonCodes": [
                    "SCHEMA_INVALID"
                ],
            },
            None,
        )

    uri = obj.get("uri")

    if not valid_uri(uri):
        reasons.append("URI_INVALID")

    generation = obj.get("generation")
    fetched_generation = obj.get(
        "fetchedGeneration"
    )

    generation_valid = (
        isinstance(generation, str)
        and GEN_RE.fullmatch(
            generation
        ) is not None
    )

    fetched_valid = (
        isinstance(
            fetched_generation,
            str,
        )
        and GEN_RE.fullmatch(
            fetched_generation
        ) is not None
    )

    if not generation_valid or not fetched_valid:
        reasons.append(
            "GENERATION_INVALID"
        )

    if (
        generation_valid
        and fetched_valid
        and generation != fetched_generation
    ):
        reasons.append(
            "GENERATION_MISMATCH"
        )

    crc = obj.get("crc32c")

    crc_valid = (
        isinstance(crc, str)
        and CRC_RE.fullmatch(crc)
        is not None
    )

    if not crc_valid:
        reasons.append(
            "CRC32C_INVALID"
        )

    schema_id = obj.get("schemaId")

    if schema_id != "training-v1":
        reasons.append(
            "SCHEMA_INVALID"
        )

    content = obj.get("content")

    rows = None

    if not isinstance(content, str):
        reasons.append(
            "SCHEMA_INVALID"
        )
    else:
        rows, content_error = parse_jsonl(
            content
        )

        if content_error is not None:
            reasons.append(content_error)

        # Only compare CRC when:
        # content is a string AND CRC syntax is valid.
        if crc_valid:
            actual_crc = crc32c_hex(
                content.encode("utf-8")
            )

            if actual_crc != crc:
                reasons.append(
                    "CRC32C_MISMATCH"
                )

    reasons = reason_sort(reasons)

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
            None,
        )

    return None, rows


# ============================================================
# ROW SERIALIZATION
# ============================================================

def row_json(row):
    return compact_json(
        {
            "id": row["id"],
            "entity": row["entity"],
            "eventTime": row["eventTime"],
            "revision": row["revision"],
            "text": row["text"],
        }
    )


def row_sort_key(row):
    return (
        utf8(row["id"]),
        utf8(row_json(row)),
    )


# ============================================================
# CONTAMINATION WORD SET
# ============================================================

def unicode_word_set(value):
    result = set()
    current = []

    for ch in value.lower():
        category = unicodedata.category(ch)

        if (
            category.startswith("L")
            or category.startswith("N")
        ):
            current.append(ch)
        else:
            if current:
                result.add(
                    "".join(current)
                )
                current = []

    if current:
        result.add(
            "".join(current)
        )

    return result


def contamination_words(row):
    return unicode_word_set(
        row["text"]
    )


def jaccard(a, b):
    if not a and not b:
        return 1.0

    union = a | b

    if not union:
        return 1.0

    return len(a & b) / len(union)


# ============================================================
# DIGEST
# ============================================================

def split_digest(rows):
    payload = bytearray()

    for row in rows:
        payload.extend(
            row_json(row).encode("utf-8")
        )
        payload.extend(b"\n")

    return hashlib.sha256(
        bytes(payload)
    ).hexdigest()


# ============================================================
# MERGE REJECTIONS
# ============================================================

def merge_row_rejections(rejections):
    merged = {}

    for item in rejections:
        row_id = item["id"]

        if row_id not in merged:
            merged[row_id] = set()

        merged[row_id].update(
            item["reasonCodes"]
        )

    result = []

    for row_id, codes in merged.items():
        result.append(
            {
                "id": row_id,
                "reasonCodes": reason_sort(
                    codes
                ),
            }
        )

    result.sort(
        key=lambda x: (
            utf8(x["id"]),
            utf8(compact_json(x)),
        )
    )

    return result


# ============================================================
# API
# ============================================================

@app.post("/build-corpus")
async def build_corpus(request: Request):

    # --------------------------------------------------------
    # Request parsing
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

    if not isinstance(body, dict):
        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    if (
        "policy" not in body
        or "objects" not in body
    ):
        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    if not isinstance(
        body["objects"],
        list,
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
        threshold,
    ) = validate_policy(
        body["policy"]
    )

    rejected_objects = []
    rejected_rows = []
    lineage = []
    source_rows = []

    # --------------------------------------------------------
    # Objects
    # --------------------------------------------------------

    for obj in body["objects"]:

        rejection, rows = inspect_object(obj)

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

        source_rows.extend(rows)

    # --------------------------------------------------------
    # Deduplication
    # --------------------------------------------------------

    groups = {}

    for row in source_rows:
        key = (
            row["entity"],
            row["eventTime"],
            row["text"],
        )

        groups.setdefault(
            key,
            [],
        ).append(row)

    retained = []

    for candidates in groups.values():

        # Highest revision wins.
        # UTF-8 smallest ID wins on revision tie.
        candidates.sort(
            key=lambda row: (
                -row["revision"],
                utf8(row["id"]),
            )
        )

        winner = candidates[0]

        retained.append(winner)

        for loser in candidates[1:]:
            rejected_rows.append(
                {
                    "id": loser["id"],
                    "reasonCodes": [
                        "DUPLICATE"
                    ],
                }
            )

    # --------------------------------------------------------
    # Policy / time
    # --------------------------------------------------------

    eligible = []

    for row in retained:

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

        event_dt = parse_time(
            row["eventTime"]
        )

        if (
            event_dt < min_time
            or event_dt > max_time
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

        eligible.append(row)

    # --------------------------------------------------------
    # Deterministic split
    # --------------------------------------------------------

    splits = {
        "train": [],
        "validation": [],
        "test": [],
    }

    for row in eligible:

        first_byte = hashlib.sha256(
            utf8(row["entity"])
        ).digest()[0]

        bucket = first_byte % 10

        if bucket <= 5:
            splits["train"].append(row)

        elif bucket <= 7:
            splits["validation"].append(row)

        else:
            splits["test"].append(row)

    # --------------------------------------------------------
    # Train contamination
    # --------------------------------------------------------

    train_word_sets = [
        contamination_words(row)
        for row in splits["train"]
    ]

    for split_name in (
        "validation",
        "test",
    ):

        kept = []

        for row in splits[split_name]:

            current_words = contamination_words(
                row
            )

            contaminated = False

            for train_words in train_word_sets:

                if (
                    jaccard(
                        current_words,
                        train_words,
                    )
                    >= threshold
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

    # --------------------------------------------------------
    # Sort split rows
    # --------------------------------------------------------

    for split_name in splits:
        splits[split_name].sort(
            key=row_sort_key
        )

    # --------------------------------------------------------
    # Rejected objects
    # --------------------------------------------------------

    for item in rejected_objects:
        item["reasonCodes"] = reason_sort(
            item["reasonCodes"]
        )

    rejected_objects.sort(
        key=lambda item: (
            (
                utf8(item["uri"])
                if isinstance(
                    item["uri"],
                    str,
                )
                else b""
            ),
            utf8(compact_json(item)),
        )
    )

    # --------------------------------------------------------
    # Rejected rows
    # --------------------------------------------------------

    rejected_rows = merge_row_rejections(
        rejected_rows
    )

    # --------------------------------------------------------
    # Lineage
    # --------------------------------------------------------

    lineage.sort(
        key=lambda item: (
            utf8(item["uri"]),
            utf8(compact_json(item)),
        )
    )

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
        "digests": {
            "train": split_digest(
                splits["train"]
            ),
            "validation": split_digest(
                splits["validation"]
            ),
            "test": split_digest(
                splits["test"]
            ),
        },
        "lineage": lineage,
    }


@app.get("/")
def root():
    return {"status": "ok"}