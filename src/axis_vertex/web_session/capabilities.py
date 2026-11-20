"""Public capability DTO validation from the frozen C0 record snapshot."""
from __future__ import annotations

import json
from importlib.resources import files

from .models import JsonObject, SessionError, integer, obj, strings, uuid_text

_snapshot = obj(json.loads(files(__package__).joinpath('wire-records.json').read_text()))
_records = _snapshot['records']
if not isinstance(_records, list):
    raise RuntimeError('invalid packaged C0 records')
_RECORDS = {str(obj(r)['record']): obj(r) for r in _records}
_ENUMS = obj(_snapshot['enumValues'])


def parse_capabilities(name: str, value: object) -> JsonObject:
    """Reject unknown/private fields and validate the complete public DTO tree."""
    schema = _RECORDS[name]
    fields = {component.rsplit(' ', 1)[1]: component.rsplit(' ', 1)[0]
              for component in strings(schema['components'])}
    nullable = strings(schema['nullable'])
    v = obj(value)
    if v.keys() - fields.keys() or fields.keys() - v.keys() - set(nullable):
        raise SessionError('IAM_RESPONSE_INVALID', 502)
    result: JsonObject = {}
    for key, kind in fields.items():
        item = v.get(key)
        if item is None:
            if key not in nullable:
                raise SessionError('IAM_RESPONSE_INVALID', 502)
            result[key] = None
        else:
            result[key] = _field(kind, item)
    return result


def _field(kind: str, value: object) -> object:
    if kind.startswith('List<'):
        if not isinstance(value, list):
            raise SessionError('IAM_RESPONSE_INVALID', 502)
        return [_field(kind[5:-1], item) for item in value]
    if kind == 'boolean':
        if type(value) is not bool:
            raise SessionError('IAM_RESPONSE_INVALID', 502)
        return value
    if kind == 'int':
        return integer(value)
    if kind in {'String', 'UUID'} or kind in _ENUMS:
        if not isinstance(value, str):
            raise SessionError('IAM_RESPONSE_INVALID', 502)
        if kind == 'UUID':
            uuid_text(value)
        if kind in _ENUMS and value not in strings(_ENUMS[kind]):
            raise SessionError('IAM_RESPONSE_INVALID', 502)
        return value
    return parse_capabilities(kind.rsplit('.', 1)[-1], value)
