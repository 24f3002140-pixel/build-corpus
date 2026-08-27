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


def cjson(x):
    return json.dumps(
        x,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def ub(x):
    return x.encode("utf-8")


def sorted_unique(values):
    return sorted(
        set(values),
        key=lambda x: x.encode("utf-8"),
    )


# ============================================================
# CRC32C
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


def crc_hex(data):
    return f"{crc32c(data):08x}"


# ============================================================
# URI
# ============================================================

def valid_uri(uri):
    if not isinstance(uri, str):
        return False

    if not uri.startswith("gs://"):
        return False

    remainder = uri[5:]

    if "/" not in remainder:
        return False

    bucket, obj = remainder.split("/", 1)

    if not bucket or not obj:
        return False

    return True


# ============================================================
# TIME
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

    fraction = m.group(7) or ""
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

    millis = int(
        fraction.ljust(3, "0")
    ) if fraction else 0

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


def canonical_time(value):
    dt = parse_time(value)

    if dt is None:
        return None

    return (
        dt.strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{dt.microsecond // 1000:03d}Z"
    )


# ============================================================
# CANONICALIZATION
# ============================================================

def canon(value):
    value = unicodedata.normalize(
        "NFKC",
        value,
    )
    value = value.lower()
    return " ".join(value.split())


# ============================================================
# POLICY
# ============================================================

def policy_info(policy):
    if not isinstance(policy, dict):
        return False, None, None, None

    minimum = parse_time(
        policy.get("minTime")
    )

    maximum = parse_time(
        policy.get("maxTime")
    )

    threshold = policy.get(
        "contaminationThreshold"
    )

    if minimum is None or maximum is None:
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

    if minimum > maximum:
        return False, None, None, None

    return (
        True,
        minimum,
        maximum,
        threshold,
    )


# ============================================================
# JSONL VALIDATION
# ============================================================

def parse_content(content):

    if not isinstance(content, str):
        return None, "SCHEMA_INVALID"

    lines = content.splitlines()

    rows = []

    for line in lines:

        if line.strip() == "":
            continue

        try:
            value = json.loads(line)
        except Exception:
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
                "entity": canon(
                    value["entity"]
                ),
                "eventTime": event_time,
                "revision": revision,
                "text": canon(
                    value["text"]
                ),
            }
        )

    if len(rows) == 0:
        return None, "SCHEMA_INVALID"

    return rows, None


# ============================================================
# OBJECT CHECK
# ============================================================

def inspect_object(obj):

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

    reasons = []

    # URI
    if not valid_uri(uri):
        reasons.append("URI_INVALID")

    # Generations
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

    # CRC syntax
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

    # Schema ID
    if obj.get("schemaId") != "training-v1":
        reasons.append(
            "SCHEMA_INVALID"
        )

    # Content / JSONL
    content = obj.get("content")

    rows = None

    if not isinstance(content, str):

        reasons.append(
            "SCHEMA_INVALID"
        )

    else:

        rows, error = parse_content(
            content
        )

        if error is not None:
            reasons.append(error)

    # CRC mismatch is checked ONLY when:
    # content is a string AND CRC syntax is valid.
    if (
        isinstance(content, str)
        and crc_ok
    ):

        actual = crc_hex(
            content.encode("utf-8")
        )

        if actual != supplied_crc:
            reasons.append(
                "CRC32C_MISMATCH"
            )

    reasons = sorted_unique(reasons)

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

def serialize_row(row):
    return cjson(
        {
            "id": row["id"],
            "entity": row["entity"],
            "eventTime": row["eventTime"],
            "revision": row["revision"],
            "text": row["text"],
        }
    )


# ============================================================
# WORD SET
# ============================================================

def words(value):

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
    return words(
        row["entity"]
        + " "
        + row["text"]
    )


def similarity(a, b):

    if not a and not b:
        return 1.0

    union = a | b

    if not union:
        return 1.0

    return len(a & b) / len(union)


# ============================================================
# DIGEST
# ============================================================

def digest(rows):

    data = bytearray()

    for row in rows:
        data.extend(
            serialize_row(row).encode(
                "utf-8"
            )
        )
        data.extend(b"\n")

    return hashlib.sha256(
        bytes(data)
    ).hexdigest()


# ============================================================
# API
# ============================================================

@app.post("/build-corpus")
async def build_corpus(request: Request):

    # Request must be valid JSON.
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    # Root must be object.
    if not isinstance(body, dict):
        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    # Policy must exist.
    if "policy" not in body:
        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    # Objects must exist and be array.
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

    valid_policy, minimum, maximum, threshold = (
        policy_info(body["policy"])
    )

    rejected_objects = []
    rejected_rows = []
    lineage = []
    all_rows = []

    # ========================================================
    # OBJECT PROCESSING
    # ========================================================

    for obj in body["objects"]:

        rejection, rows = inspect_object(obj)

        if rejection is not None:

            rejected_objects.append(
                rejection
            )

        else:

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

            all_rows.extend(rows)

    # ========================================================
    # DEDUPLICATION
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

    retained = []

    for candidates in groups.values():

        candidates.sort(
            key=lambda row: (
                -row["revision"],
                ub(row["id"]),
                ub(serialize_row(row)),
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

    # ========================================================
    # POLICY / WINDOW
    # ========================================================

    eligible = []

    for row in retained:

        if not valid_policy:

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

        if dt < minimum or dt > maximum:

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

    # ========================================================
    # SPLIT
    # ========================================================

    split = {
        "train": [],
        "validation": [],
        "test": [],
    }

    for row in eligible:

        first_byte = hashlib.sha256(
            row["entity"].encode("utf-8")
        ).digest()[0]

        bucket = first_byte % 10

        if bucket <= 5:
            split["train"].append(row)

        elif bucket <= 7:
            split["validation"].append(row)

        else:
            split["test"].append(row)

    # ========================================================
    # CONTAMINATION
    # ========================================================

    train_sets = [
        row_words(row)
        for row in split["train"]
    ]

    for name in (
        "validation",
        "test",
    ):

        kept = []

        for row in split[name]:

            current = row_words(row)

            contaminated = False

            for train in train_sets:

                if (
                    similarity(
                        current,
                        train,
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

        split[name] = kept

    # ========================================================
    # SORT SPLITS
    # ========================================================

    for name in split:

        split[name].sort(
            key=lambda row: (
                ub(row["id"]),
                ub(serialize_row(row)),
            )
        )

    # ========================================================
    # MERGE ROW REJECTIONS
    # ========================================================

    merged = {}

    for rejection in rejected_rows:

        rid = rejection["id"]

        if rid not in merged:
            merged[rid] = set()

        merged[rid].update(
            rejection["reasonCodes"]
        )

    rejected_rows = [
        {
            "id": rid,
            "reasonCodes": sorted_unique(
                codes
            ),
        }
        for rid, codes in merged.items()
    ]

    rejected_rows.sort(
        key=lambda item: (
            ub(item["id"]),
            ub(cjson(item)),
        )
    )

    # ========================================================
    # SORT OBJECT REJECTIONS
    # ========================================================

    for rejection in rejected_objects:
        rejection["reasonCodes"] = sorted_unique(
            rejection["reasonCodes"]
        )

    rejected_objects.sort(
        key=lambda item: (
            (
                ub(item["uri"])
                if isinstance(
                    item["uri"],
                    str,
                )
                else b("")
            ),
            ub(cjson(item)),
        )
    )

    # ========================================================
    # LINEAGE
    # ========================================================

    lineage.sort(
        key=lambda item: (
            ub(item["uri"]),
            ub(cjson(item)),
        )
    )

    # ========================================================
    # RESPONSE
    # ========================================================

    return {
        "splits": {
            "train": split["train"],
            "validation": split["validation"],
            "test": split["test"],
        },
        "rejectedObjects": rejected_objects,
        "rejectedRows": rejected_rows,
        "digests": {
            "train": digest(
                split["train"]
            ),
            "validation": digest(
                split["validation"]
            ),
            "test": digest(
                split["test"]
            ),
        },
        "lineage": lineage,
    }


@app.get("/")
def root():
    return {"status": "ok"}