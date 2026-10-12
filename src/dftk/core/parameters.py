# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
"""Dependency-free validation of the JSON Schema subset used by tool contracts."""
from __future__ import annotations
import math


class ParameterError(ValueError):
    pass


def validate(value, schema, location='params', depth=0):
    if depth > 64:
        raise ParameterError(f'{location}: parameter nesting exceeds 64 levels')
    if not isinstance(schema, dict):
        return
    if 'anyOf' in schema:
        for candidate in schema['anyOf']:
            try:
                validate(value, candidate, location, depth + 1)
                break
            except ParameterError:
                pass
        else:
            raise ParameterError(f'{location}: no allowed schema matches')
    typ = schema.get('type')
    types = typ if isinstance(typ, list) else [typ] if typ else []
    def matches(kind):
        return {'null': value is None, 'string': isinstance(value, str),
                'boolean': isinstance(value, bool), 'integer': isinstance(value, int) and not isinstance(value, bool),
                'number': isinstance(value, (int, float)) and not isinstance(value, bool),
                'object': isinstance(value, dict), 'array': isinstance(value, list)}.get(kind, True)
    if types and not any(matches(kind) for kind in types):
        raise ParameterError(f'{location}: expected {typ}')
    if 'enum' in schema and value not in schema['enum']:
        raise ParameterError(f'{location}: expected one of {schema["enum"]}')
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            raise ParameterError(f'{location}: number must be finite')
        for key, bad in [('minimum', lambda n: value < n), ('maximum', lambda n: value > n),
                         ('exclusiveMinimum', lambda n: value <= n), ('exclusiveMaximum', lambda n: value >= n)]:
            if key in schema and bad(schema[key]):
                raise ParameterError(f'{location}: violates {key}={schema[key]}')
    if isinstance(value, (str, list)):
        low, high = ('minLength', 'maxLength') if isinstance(value, str) else ('minItems', 'maxItems')
        if low in schema and len(value) < schema[low] or high in schema and len(value) > schema[high]:
            raise ParameterError(f'{location}: length exceeds declared bounds')
    if isinstance(value, list) and isinstance(schema.get('items'), dict):
        for index, item in enumerate(value):
            validate(item, schema['items'], f'{location}[{index}]', depth + 1)
    if isinstance(value, dict):
        for key in schema.get('required', []):
            if key not in value:
                raise ParameterError(f'{location}: required parameter {key!r} is missing')
        properties = schema.get('properties', {})
        for key, item in value.items():
            if key in properties:
                validate(item, properties[key], f'{location}.{key}', depth + 1)
            elif schema.get('additionalProperties') is False:
                raise ParameterError(f'{location}: unknown parameter {key!r}')
