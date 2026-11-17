"""Minimal JSON-schema subset validator for LLM outputs.

Covers what our task schemas use: type, properties, required,
additionalProperties (bool), enum, items, min/maxLength, minimum/maximum,
maxItems. Anything the model returns outside the schema is rejected — the
output is data for a human to review, never trusted structure.
"""

from __future__ import annotations

from typing import Any

_TYPES: dict[str, tuple[type, ...]] = {
    "object": (dict,),
    "array": (list,),
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "null": (type(None),),
}


def _type_ok(expected: str, value: Any) -> bool:
    if expected in ("integer", "number") and isinstance(value, bool):
        return False
    if expected == "integer" and isinstance(value, float):
        return value.is_integer()
    py = _TYPES.get(expected)
    return py is not None and isinstance(value, py)


def is_valid(schema: dict[str, Any], value: Any, _depth: int = 0) -> bool:
    if _depth > 32 or not isinstance(schema, dict):
        return False
    expected = schema.get("type")
    if expected is not None:
        options = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(t, value) for t in options):
            return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    if isinstance(value, str):
        if len(value) < int(schema.get("minLength", 0)):
            return False
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            return False
        if "maximum" in schema and value > schema["maximum"]:
            return False
    if isinstance(value, list):
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            return False
        items = schema.get("items")
        if isinstance(items, dict) and not all(is_valid(items, v, _depth + 1) for v in value):
            return False
    if isinstance(value, dict):
        props: dict[str, Any] = schema.get("properties") or {}
        for key in schema.get("required") or ():
            if key not in value:
                return False
        if schema.get("additionalProperties") is False and any(k not in props for k in value):
            return False
        for key, sub in props.items():
            if key in value and not is_valid(sub, value[key], _depth + 1):
                return False
    return True
