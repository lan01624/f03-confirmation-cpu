from __future__ import annotations
import base64, hashlib, json

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_json(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def decode_index_bitset(payload: str, *, source_count: int) -> list[int]:
    raw = base64.b64decode(payload, validate=True)
    expected_bytes = (source_count + 7) // 8
    if len(raw) != expected_bytes:
        raise ValueError(f"expected {expected_bytes} bitset bytes, got {len(raw)}")
    if source_count % 8 and raw and raw[-1] >> (source_count % 8):
        raise ValueError("bitset has set padding bits")
    return [index for index in range(source_count) if raw[index // 8] & (1 << (index % 8))]
