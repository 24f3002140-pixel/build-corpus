import hashlib
import json
import math
import re
import unicodedata
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

SAFE_INT_MAX = 9007199254740991

GENERATION_RE = re.compile(r"^[0-9]+$")
CRC32C_RE = re.compile(r"^[0-9a-f]{8}$")

TIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"
    r"T(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,3}))?"
    r"(Z|[+-]\d{2}:\d{2})$"
)

REQUIRED_ROW_KEYS = {
    "id",
    "entity",
    "eventTime",
    "revision",
    "text",
}


# ============================================================
# DETERMINISTIC JSON
# ============================================================

def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def utf8(value):
    return value.encode("utf-8")


def sort_codes(codes):
    return sorted(
        set(codes),
        key=lambda x: x.encode("utf-8"),
    )


# ============================================================
# CRC32C CASTAGNOLI
# ============================================================

CRC_TABLE = []

for i in range(256):
    crc = i

    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0x82F63B78
        else:
            crc >>= 1

    CRC_TABLE.append(crc)


def crc32c(data):
    crc = 0xFFFFFFFF

    for byte in data:
        crc = (
            CRC_TABLE[(crc ^ byte) & 0xFF]
            ^ (crc >> 8)
        )

    return crc ^ 0xFFFFFFFF


def crc32c_hex(data):
    return format(
        crc32c(data),
        "08x",
    )


# ============================================================
# URI
# ============================================================

def is_valid_uri(value):
    if not isinstance(value, str):
        return False

    if not value.startswith("gs://"):
        return False

    rest = value[5:]

    if "/" not in rest:
        return False

    bucket, object_name = rest.split("/", 1)

    if not bucket:
        return False

    if not object_name:
        return False

    return True


# ============================================================
# TIME
# ============================================================

def parse_timestamp(value):

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

        if (
            offset_hour == 14
            and offset_minute != 0
        ):
            return None

        sign = 1 if zone[0] == "+" else -1

        tz = timezone(
            sign * timedelta(
                hours=offset_hour,
                minutes=offset_minute,
            )
        )

    milliseconds = (
        int(fraction.ljust(3, "0"))
        if fraction
        else 0
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


def normalize_timestamp(value):

    dt = parse_timestamp(value)

    if dt is None:
        return None

    return (
        dt.strftime(
            "%Y-%m-%dT%H:%M:%S."
        )
        + f"{dt.microsecond // 1000:03d}Z"
    )


# ============================================================
# CANONICAL TEXT
# ============================================================

def canonicalize(value):

    value = unicodedata.normalize(
        "NFKC",
        value,
    )

    value = value.lower()

    return " ".join(value.split())


# ============================================================
# POLICY
# ============================================================

def validate_policy(policy):

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
        or not isinstance(
            threshold,
            (int, float),
        )
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

    # A file containing only whitespace is empty.
    if content.strip() == "":
        return None, "SCHEMA_INVALID"

    rows = []

    for raw_line in content.splitlines():

        if raw_line.strip() == "":
            continue

        try:
            parsed = json.loads(raw_line)

        except Exception:
            return None, "JSONL_INVALID"

        if not isinstance(parsed, dict):
            return None, "SCHEMA_INVALID"

        if set(parsed.keys()) != REQUIRED_ROW_KEYS:
            return None, "SCHEMA_INVALID"

        if not isinstance(parsed["id"], str):
            return None, "SCHEMA_INVALID"

        if not isinstance(parsed["entity"], str):
            return None, "SCHEMA_INVALID"

        if not isinstance(parsed["eventTime"], str):
            return None, "SCHEMA_INVALID"

        if not isinstance(parsed["text"], str):
            return None, "SCHEMA_INVALID"

        revision = parsed["revision"]

        if isinstance(revision, bool):
            return None, "SCHEMA_INVALID"

        if not isinstance(revision, int):
            return None, "SCHEMA_INVALID"

        if revision < 0:
            return None, "SCHEMA_INVALID"

        if revision > SAFE_INT_MAX:
            return None, "SCHEMA_INVALID"

        normalized_time = normalize_timestamp(
            parsed["eventTime"]
        )

        if normalized_time is None:
            return None, "SCHEMA_INVALID"

        rows.append(
            {
                "id": parsed["id"],
                "entity": canonicalize(
                    parsed["entity"]
                ),
                "eventTime": normalized_time,
                "revision": revision,
                "text": canonicalize(
                    parsed["text"]
                ),
            }
        )

    if not rows:
        return None, "SCHEMA_INVALID"

    return rows, None


# ============================================================
# OBJECT VALIDATION
# ============================================================

def validate_object(obj):

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

    reasons = []

    # --------------------------------------------------------
    # URI
    # --------------------------------------------------------

    uri = obj.get("uri")

    if not is_valid_uri(uri):
        reasons.append(
            "URI_INVALID"
        )

    # --------------------------------------------------------
    # GENERATIONS
    # --------------------------------------------------------

    generation = obj.get("generation")
    fetched = obj.get("fetchedGeneration")

    generation_valid = (
        isinstance(generation, str)
        and GENERATION_RE.fullmatch(
            generation
        ) is not None
    )

    fetched_valid = (
        isinstance(fetched, str)
        and GENERATION_RE.fullmatch(
            fetched
        ) is not None
    )

    if not generation_valid or not fetched_valid:
        reasons.append(
            "GENERATION_INVALID"
        )

    if (
        generation_valid
        and fetched_valid
        and generation != fetched
    ):
        reasons.append(
            "GENERATION_MISMATCH"
        )

    # --------------------------------------------------------
    # CRC32C
    # --------------------------------------------------------

    supplied_crc = obj.get("crc32c")

    crc_valid = (
        isinstance(supplied_crc, str)
        and CRC32C_RE.fullmatch(
            supplied_crc
        ) is not None
    )

    if not crc_valid:
        reasons.append(
            "CRC32C_INVALID"
        )

    # --------------------------------------------------------
    # SCHEMA ID
    # --------------------------------------------------------

    if obj.get("schemaId") != "training-v1":
        reasons.append(
            "SCHEMA_INVALID"
        )

    # --------------------------------------------------------
    # CONTENT
    # --------------------------------------------------------

    content = obj.get("content")

    parsed_rows = None

    if not isinstance(content, str):

        reasons.append(
            "SCHEMA_INVALID"
        )

    else:

        parsed_rows, error = parse_jsonl(
            content
        )

        if error is not None:
            reasons.append(error)

    # --------------------------------------------------------
    # CRC MATCH
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

    reasons = sort_codes(reasons)

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

    return None, parsed_rows


# ============================================================
# ROW SERIALIZATION
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


# ============================================================
# WORD SET / JACCARD
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


def row_words(row):

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
# DIGEST
# ============================================================

def calculate_digest(rows):

    payload = bytearray()

    for row in rows:

        payload.extend(
            serialize_row(row).encode(
                "utf-8"
            )
        )

        payload.extend(b"\n")

    return hashlib.sha256(
        bytes(payload)
    ).hexdigest()


# ============================================================
# ENDPOINT
# ============================================================

@app.post("/build-corpus")
async def build_corpus(request: Request):

    # --------------------------------------------------------
    # REQUEST PARSING
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

    # Missing policy => 400.
    if "policy" not in body:

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    # Missing/non-array objects => 400.
    if (
        "objects" not in body
        or not isinstance(
            body["objects"],
            list,
        )
    ):

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    # --------------------------------------------------------
    # POLICY
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
    # OBJECTS
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
                "generation": obj[
                    "generation"
                ],
                "crc32c": obj["crc32c"],
                "schemaId": obj[
                    "schemaId"
                ],
            }
        )

        source_rows.extend(rows)

    # --------------------------------------------------------
    # DEDUPLICATE
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

        candidates.sort(
            key=lambda row: (
                -row["revision"],
                utf8(row["id"]),
                utf8(serialize_row(row)),
            )
        )

        retained.append(
            candidates[0]
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

    # --------------------------------------------------------
    # POLICY / WINDOW
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

        event_time = parse_timestamp(
            row["eventTime"]
        )

        if (
            event_time < min_time
            or event_time > max_time
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
    # SPLIT
    # --------------------------------------------------------

    splits = {
        "train": [],
        "validation": [],
        "test": [],
    }

    for row in eligible:

        entity_hash = hashlib.sha256(
            row["entity"].encode("utf-8")
        ).digest()

        bucket = entity_hash[0] % 10

        if bucket <= 5:
            splits["train"].append(row)

        elif bucket <= 7:
            splits["validation"].append(row)

        else:
            splits["test"].append(row)

    # --------------------------------------------------------
    # CONTAMINATION
    # --------------------------------------------------------

    train_word_sets = [
        row_words(row)
        for row in splits["train"]
    ]

    for split_name in (
        "validation",
        "test",
    ):

        kept = []

        for row in splits[split_name]:

            candidate_words = row_words(row)

            contaminated = False

            for train_words in train_word_sets:

                if (
                    jaccard(
                        candidate_words,
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
    # SORT SPLITS
    # --------------------------------------------------------

    for name in splits:

        splits[name].sort(
            key=lambda row: (
                utf8(row["id"]),
                utf8(serialize_row(row)),
            )
        )

    # --------------------------------------------------------
    # COMBINE REJECTED ROWS
    # --------------------------------------------------------

    rejection_map = {}

    for item in rejected_rows:

        row_id = item["id"]

        if row_id not in rejection_map:
            rejection_map[row_id] = set()

        rejection_map[row_id].update(
            item["reasonCodes"]
        )

    rejected_rows = [
        {
            "id": row_id,
            "reasonCodes": sort_codes(codes),
        }
        for row_id, codes
        in rejection_map.items()
    ]

    rejected_rows.sort(
        key=lambda item: (
            utf8(item["id"]),
            utf8(compact_json(item)),
        )
    )

    # --------------------------------------------------------
    # OBJECT REJECTIONS
    # --------------------------------------------------------

    for item in rejected_objects:

        item["reasonCodes"] = sort_codes(
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
    # LINEAGE
    # --------------------------------------------------------

    lineage.sort(
        key=lambda item: (
            utf8(item["uri"]),
            utf8(compact_json(item)),
        )
    )

    # --------------------------------------------------------
    # DIGESTS
    # --------------------------------------------------------

    digests = {
        "train": calculate_digest(
            splits["train"]
        ),
        "validation": calculate_digest(
            splits["validation"]
        ),
        "test": calculate_digest(
            splits["test"]
        ),
    }

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return {
        "splits": {
            "train": splits["train"],
            "validation": splits[
                "validation"
            ],
            "test": splits["test"],
        },
        "rejectedObjects":
            rejected_objects,
        "rejectedRows":
            rejected_rows,
        "digests":
            digests,
        "lineage":
            lineage,
    }


@app.get("/")
def health():
    return {"status": "ok"}