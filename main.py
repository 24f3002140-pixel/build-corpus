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

ROW_KEYS = {
    "id",
    "entity",
    "eventTime",
    "revision",
    "text",
}


# ============================================================
# BASIC HELPERS
# ============================================================

def compact(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def b(value):
    return value.encode("utf-8")


def sorted_codes(codes):
    return sorted(
        set(codes),
        key=lambda x: x.encode("utf-8"),
    )


# ============================================================
# CRC32C / CASTAGNOLI
# ============================================================

CRC_TABLE = []

for n in range(256):
    crc = n
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


def crc32c_string(data):
    return f"{crc32c(data):08x}"


# ============================================================
# URI
# ============================================================

def valid_uri(value):
    if not isinstance(value, str):
        return False

    if not value.startswith("gs://"):
        return False

    rest = value[5:]

    # Must contain bucket/object.
    if "/" not in rest:
        return False

    bucket, object_name = rest.split("/", 1)

    if bucket == "":
        return False

    if object_name == "":
        return False

    return True


# ============================================================
# TIMESTAMP
# ============================================================

def parse_time(value):

    if not isinstance(value, str):
        return None

    m = TIME_RE.fullmatch(value)

    if m is None:
        return None

    year = int(m.group(1))
    month = int(m.group(2))
    day = int(m.group(3))
    hour = int(m.group(4))
    minute = int(m.group(5))
    second = int(m.group(6))

    frac = m.group(7) or ""
    zone = m.group(8)

    if zone == "Z":
        tz = timezone.utc
    else:
        oh = int(zone[1:3])
        om = int(zone[4:6])

        if oh > 14:
            return None

        if om > 59:
            return None

        if oh == 14 and om != 0:
            return None

        sign = 1 if zone[0] == "+" else -1

        tz = timezone(
            sign * timedelta(
                hours=oh,
                minutes=om,
            )
        )

    ms = int(frac.ljust(3, "0")) if frac else 0

    try:
        dt = datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            ms * 1000,
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
# CANONICAL TEXT
# ============================================================

def canonical_text(value):
    value = unicodedata.normalize(
        "NFKC",
        value,
    )

    value = value.lower()

    # Python str.split() uses Unicode whitespace.
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

    try:
        threshold_float = float(threshold)
    except Exception:
        return False, None, None, None

    if not math.isfinite(threshold_float):
        return False, None, None, None

    if (
        threshold_float < 0
        or threshold_float > 1
    ):
        return False, None, None, None

    if min_time > max_time:
        return False, None, None, None

    return (
        True,
        min_time,
        max_time,
        threshold_float,
    )


# ============================================================
# JSONL
# ============================================================

def parse_jsonl(content):

    if not isinstance(content, str):
        return [], "SCHEMA_INVALID"

    # Split exactly on LF.
    lines = content.split("\n")

    parsed = []

    for line in lines:

        # Ignore blank lines.
        if line.strip() == "":
            continue

        # CRLF support.
        if line.endswith("\r"):
            line = line[:-1]

        try:
            obj = json.loads(line)
        except Exception:
            return [], "JSONL_INVALID"

        # Parsed value must be object.
        if not isinstance(obj, dict):
            return [], "SCHEMA_INVALID"

        # Exactly the required keys.
        if set(obj.keys()) != ROW_KEYS:
            return [], "SCHEMA_INVALID"

        # String fields.
        if not isinstance(obj["id"], str):
            return [], "SCHEMA_INVALID"

        if not isinstance(obj["entity"], str):
            return [], "SCHEMA_INVALID"

        if not isinstance(obj["eventTime"], str):
            return [], "SCHEMA_INVALID"

        if not isinstance(obj["text"], str):
            return [], "SCHEMA_INVALID"

        # Revision.
        revision = obj["revision"]

        if isinstance(revision, bool):
            return [], "SCHEMA_INVALID"

        if not isinstance(revision, int):
            return [], "SCHEMA_INVALID"

        if revision < 0:
            return [], "SCHEMA_INVALID"

        if revision > SAFE_INT_MAX:
            return [], "SCHEMA_INVALID"

        # Event time.
        et = canonical_time(
            obj["eventTime"]
        )

        if et is None:
            return [], "SCHEMA_INVALID"

        parsed.append(
            {
                "id": obj["id"],
                "entity": canonical_text(
                    obj["entity"]
                ),
                "eventTime": et,
                "revision": revision,
                "text": canonical_text(
                    obj["text"]
                ),
            }
        )

    # At least one row.
    if len(parsed) == 0:
        return [], "SCHEMA_INVALID"

    return parsed, None


# ============================================================
# OBJECT VALIDATION
# ============================================================

def validate_object(obj):

    # If the array contains a non-object.
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

    uri = obj.get("uri")

    # --------------------------------------------------------
    # URI
    # --------------------------------------------------------

    if not valid_uri(uri):
        reasons.append(
            "URI_INVALID"
        )

    # --------------------------------------------------------
    # GENERATIONS
    # --------------------------------------------------------

    generation = obj.get("generation")
    fetched = obj.get("fetchedGeneration")

    generation_ok = (
        isinstance(generation, str)
        and GEN_RE.fullmatch(
            generation
        ) is not None
    )

    fetched_ok = (
        isinstance(fetched, str)
        and GEN_RE.fullmatch(
            fetched
        ) is not None
    )

    if not generation_ok or not fetched_ok:
        reasons.append(
            "GENERATION_INVALID"
        )

    if (
        generation_ok
        and fetched_ok
        and generation != fetched
    ):
        reasons.append(
            "GENERATION_MISMATCH"
        )

    # --------------------------------------------------------
    # CRC
    # --------------------------------------------------------

    supplied_crc = obj.get("crc32c")

    crc_ok = (
        isinstance(supplied_crc, str)
        and CRC_RE.fullmatch(
            supplied_crc
        ) is not None
    )

    if not crc_ok:
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

    if not isinstance(content, str):

        reasons.append(
            "SCHEMA_INVALID"
        )

        rows = None

    else:

        rows, jsonl_error = parse_jsonl(
            content
        )

        if jsonl_error is not None:
            reasons.append(
                jsonl_error
            )

    # --------------------------------------------------------
    # CRC MISMATCH
    #
    # Only when content is string and CRC syntax is valid.
    # --------------------------------------------------------

    if (
        isinstance(content, str)
        and crc_ok
    ):

        actual = crc32c_string(
            content.encode("utf-8")
        )

        if actual != supplied_crc:
            reasons.append(
                "CRC32C_MISMATCH"
            )

    reasons = sorted_codes(
        reasons
    )

    if reasons:

        return (
            {
                "uri": (
                    uri
                    if isinstance(
                        uri,
                        str,
                    )
                    else None
                ),
                "reasonCodes": reasons,
            },
            None,
        )

    return None, rows


# ============================================================
# ROW JSON
# ============================================================

def row_json(row):

    return compact(
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

def word_set(value):

    result = set()
    current = []

    for ch in value.lower():

        cat = unicodedata.category(ch)

        if (
            cat.startswith("L")
            or cat.startswith("N")
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

    return word_set(
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

    # Missing policy.
    if "policy" not in body:
        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    # Missing/non-array objects.
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

    valid_rows = []

    # --------------------------------------------------------
    # OBJECTS
    # --------------------------------------------------------

    for obj in body["objects"]:

        rejection, rows = validate_object(
            obj
        )

        if rejection is not None:

            rejected_objects.append(
                rejection
            )

            continue

        # Valid object -> lineage.
        lineage.append(
            {
                "uri": obj["uri"],
                "generation":
                    obj["generation"],
                "crc32c":
                    obj["crc32c"],
                "schemaId":
                    obj["schemaId"],
            }
        )

        valid_rows.extend(rows)

    # --------------------------------------------------------
    # DEDUPLICATION
    # --------------------------------------------------------

    groups = {}

    for row in valid_rows:

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
            key=lambda r: (
                -r["revision"],
                b(r["id"]),
                b(row_json(r)),
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

        dt = parse_time(
            row["eventTime"]
        )

        if (
            dt < min_time
            or dt > max_time
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
    # SPLITTING
    # --------------------------------------------------------

    splits = {
        "train": [],
        "validation": [],
        "test": [],
    }

    for row in eligible:

        digest = hashlib.sha256(
            row["entity"].encode("utf-8")
        ).digest()

        bucket = digest[0] % 10

        if bucket <= 5:
            splits["train"].append(row)
        elif bucket <= 7:
            splits["validation"].append(row)
        else:
            splits["test"].append(row)

    # --------------------------------------------------------
    # CONTAMINATION
    # --------------------------------------------------------

    train_sets = [
        row_words(row)
        for row in splits["train"]
    ]

    for split_name in (
        "validation",
        "test",
    ):

        kept = []

        for row in splits[split_name]:

            words = row_words(row)

            contaminated = False

            for train_words in train_sets:

                if (
                    jaccard(
                        words,
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
            key=lambda r: (
                b(r["id"]),
                b(row_json(r)),
            )
        )

    # --------------------------------------------------------
    # MERGE REJECTED ROW REASONS
    # --------------------------------------------------------

    row_rejections = {}

    for item in rejected_rows:

        row_id = item["id"]

        if row_id not in row_rejections:
            row_rejections[row_id] = set()

        row_rejections[row_id].update(
            item["reasonCodes"]
        )

    rejected_rows = []

    for row_id, codes in row_rejections.items():

        rejected_rows.append(
            {
                "id": row_id,
                "reasonCodes":
                    sorted_codes(codes),
            }
        )

    rejected_rows.sort(
        key=lambda x: (
            b(x["id"]),
            b(compact(x)),
        )
    )

    # --------------------------------------------------------
    # SORT OBJECT REJECTIONS
    # --------------------------------------------------------

    for item in rejected_objects:
        item["reasonCodes"] = sorted_codes(
            item["reasonCodes"]
        )

    rejected_objects.sort(
        key=lambda x: (
            b(x["uri"])
            if isinstance(
                x["uri"],
                str,
            )
            else b(""),
            b(compact(x)),
        )
    )

    # --------------------------------------------------------
    # LINEAGE
    # --------------------------------------------------------

    lineage.sort(
        key=lambda x: (
            b(x["uri"]),
            b(compact(x)),
        )
    )

    # --------------------------------------------------------
    # DIGESTS
    # --------------------------------------------------------

    digests = {
        "train":
            split_digest(
                splits["train"]
            ),
        "validation":
            split_digest(
                splits["validation"]
            ),
        "test":
            split_digest(
                splits["test"]
            ),
    }

    # --------------------------------------------------------
    # EXACT RESPONSE
    # --------------------------------------------------------

    return {
        "splits": {
            "train":
                splits["train"],
            "validation":
                splits["validation"],
            "test":
                splits["test"],
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