from copy import deepcopy
from pickle import SHORT_BINSTRING
import string
import struct
import yaml

from runner import vrl
from rich import print
from pathlib import Path
import json
from collections import defaultdict
from typing import Iterable
import pyperclip
import re
import sys
from functools import reduce
from rich.console import Console

console = Console()

from argparse import ArgumentParser
from enum import Enum


def merge(a, b, path=None):
    "merges b into a"
    if path is None:
        path = []

    if not isinstance(b, dict) or not isinstance(a, dict):
        if a == b:
            return a
        else:
            raise Exception(f"Conflict at {path}: {a} != {b}")

    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge(a[key], b[key], path + [str(key)])
            elif isinstance(a[key], list) and isinstance(b[key], list):
                if len(a[key]) != len(b[key]):
                    raise Exception("Cannot merge lists of different length")
                for i, c in enumerate(zip(a[key], b[key])):
                    a[key][i] = merge(*c, path + [str(key)])
            elif isinstance(a[key], list) and not isinstance(b[key], list):
                print(
                    f"[yellow]WARN: Attempting to auto resolve potential '.*' conflicting at: {'.'.join(path + [str(key)])}"
                )
                merge(a[key], [b[key]], path + [str(key)])
            elif a[key] == b[key]:
                pass  # same leaf value
            else:
                # print({ "path": path, "key": key, "a": a[key], "b": b[key] })
                if {a[key], b[key]} == {"string", "boolean"}:
                    print(
                        f"WARN: Auto-coerced {'.'.join(path + [str(key)])} conflict with string -> boolean."
                    )
                    a[key]
                else:
                    msg = (
                        "Conflict at %s: %s and %s" % ".".join(path + [str(key)]),
                        a[key],
                        b[key],
                    )
                    raise Exception(msg)
        else:
            try:
                a[key] = b[key]
            except:
                breakpoint()
    return a


def traverse(dic, path=[]):
    if isinstance(dic, dict):
        for x in dic.keys():
            local_path = path[:]
            local_path.append(x)
            yield from traverse(dic[x], local_path)
    elif isinstance(dic, list):
        yield from traverse(dic[0], path)
    else:
        yield path


def deepen(j):
    d = {}
    for key, value in j.items():
        s = d
        tokens = re.findall(r"\w+", key)
        for index, (token, next_token) in enumerate(
            zip(tokens, tokens[1:] + [value]), 1
        ):
            value = (
                next_token
                if index == len(tokens)
                else []
                if next_token.isdigit()
                else {}
            )
            if isinstance(s, list):
                token = int(token)
                while token >= len(s):
                    s.append(value)
            elif token not in s:
                s[token] = value
            s = s[token]
    return d


def deep_find(obj, keys, delimiter="."):
    if type(keys) == str:
        keys = keys.split(delimiter)

    def reducer(acc, key):
        value, path = acc
        if value == None:
            return (None, None)

        if type(value) == list:
            path += "[0]"
            value = value[0]

        value = value.get(key, None)

        return (
            value,
            (f"{path}.{key}" if path else f"{key}") if value is not None else None,
        )

    return reduce(reducer, keys, (obj, ""))


def ensurepath(dic, keys):
    for i, key in enumerate(keys[:-1]):
        if type(dic) != dict:
            if dic[0] == "string":
                print(
                    f"[yellow]WARN: Fixing intermediate array object field: {'.'.join(keys[:i])}"
                )
                dic[0] = {}
            dic = dic[0]
        r = dic.setdefault(key, {})
        if r == "string":
            print(
                f"[yellow]WARN: Fixing intermediate array object field: {'.'.join(keys[:i+1])}"
            )
            r = dic[key] = {}
        dic = r
    return dic


def _to_schema(item, is_root=False):
    keys = [k for k in item["name"].split(".") if k != "*"]
    schema = {}

    if "type" not in item:
        print(f"[yellow]WARN: [white]{item}")
        return {}

    if item["type"] == "group":
        for field in item.get("fields", []):
            subkeys = [k for k in field["name"].split(".") if k != "*"]
            # print([*keys, *subkeys], field)
            field_item = ensurepath(schema, [*keys, *subkeys])
            field_schema = _to_schema(field)
            # if "aws" in schema:
            #     print(field, schema)
            # print("ss", schema, keys, field,subkeys, field_item, field_schema)
            if type(field_item) == list:
                print(
                    f"[yellow]WARN: Fixing intermediate array object field: {'.'.join([*keys, *subkeys[:-1]])}"
                )
                if field_item[0] == "string":
                    field_item[0] = field_schema
                field_item = field_item[0]
            # print(field_item, field_schema)
            try:
                merge(field_item, field_schema)
            except:
                breakpoint()
        return schema

    field_item = ensurepath(schema, keys)
    field_type = ecs_to_iceberg_type(item)

    if type(field_type) == dict:
        if field_type["type"] == "struct":
            field_type = fields_to_schema(field_type["fields"])
        elif field_type["type"] == "list":
            field_type = [field_type["element"]]
    field_item[keys[-1]] = field_type

    return schema if is_root else field_item


def ecs_to_iceberg_type(item, normalization=None):
    if item.get("normalize") and type(item.get("normalize")) != list:
        item["normalize"] = [item["normalize"]]
    normalization = (
        normalization
        or item.get("normalization")
        or [item.get("normalize") or [None]][0][0]
    )
    ecs_type = item["type"]
    ret = None
    if ecs_type == "keyword":
        ret = "string"
    elif ecs_type == "string":
        ret = "string"
    elif ecs_type == "text":
        if item["name"].endswith(".text"):
            raise
        ret = "string"
    elif ecs_type == "scaled_float":
        ret = "float"
    elif ecs_type == "date":
        ret = "timestamp"
    elif ecs_type == "wildcard":
        ret = "string"
    elif ecs_type == "float":
        ret = "float"
    elif ecs_type == "object":
        ret = "string"
    elif ecs_type == "constant_keyword":
        ret = "string"
    elif ecs_type == "boolean":
        ret = "boolean"
    elif ecs_type == "long":
        ret = "long"
    elif ecs_type == "number":
        ret = "double"
    elif ecs_type == "short":
        ret = "int"
    elif ecs_type == "double":
        ret = "double"
    elif ecs_type == "geo_point":
        ret = {
            "type": "struct",
            "fields": [
                # TODO: FIX THIS
                {"name": "lon", "type": "float",},
                {"name": "lat", "type": "float",},
            ],
        }
    elif ecs_type == "array":
        ret = {
            "type": "list",
            "element": "string",
        }
    elif ecs_type == "nested":
        ret = {
            "type": "list",
            "element": "string",
        }
    elif ecs_type == "match_only_text":
        ret = "string"
    elif ecs_type == "ip":
        ret = "string"
    elif ecs_type == "flattened":
        ret = "string"
    elif ecs_type == "alias":
        return
    elif ecs_type == "integer":
        ret = "int"

    if ret is None:
        raise Exception(f"Unknown ECS type: {ecs_type}")

    if ecs_type != "nested" and normalization == "array":
        ret = {
            "type": "list",
            "element": ret,
        }

    return ret


def expand(node):
    valid_types = {"struct", "list", "primitive"}
    if isinstance(node, dict):
        if (
            "type" not in node
            or type(node["type"]) != string
            or node["type"] not in valid_types
        ):
            node = {"type": "struct", "fields": node}
        for f in node["fields"]:
            node["fields"][f] = expand(node["fields"][f])
        return node
    elif isinstance(node, list):
        return {"type": "list", "element": expand(node[0])}

    return {"type": "primitive", "shape": node}


def expand_and_serialize_to_fields(item):
    item = deepcopy(item)
    item = {k: expand(n) for k, n in item.items()}
    # print("SSS",item)
    return serialize_to_fields(item)


def serialize_to_fields(item):
    fields = []
    for key, node in item.items():
        field = {
            "name": key,
        }
        if node["type"] == "primitive":
            field["type"] = node["shape"]
        elif node["type"] == "struct":
            field["type"] = {
                "type": "struct",
                "fields": serialize_to_fields(node["fields"]),
            }
        elif node["type"] == "list":
            field["type"] = {
                "type": "list",
                "element": serialize_to_fields({"$element": node["element"]})[0][
                    "type"
                ],
            }
        fields.append(field)

    return fields


def fields_to_schema(fields):
    # if type(fields) != list:
    #     return fields

    def reducer(acc, item):
        acc[item["name"]] = (
            (
                fields_to_schema(item["type"]["fields"])
                if item["type"]["type"] == "struct"
                else (
                    [
                        fields_to_schema(
                            [{"name": "$element", "type": item["type"]["element"]}]
                        )["$element"]
                    ]
                    if item["type"]["type"] == "list"
                    else "UNKNOWN"
                )
            )
            if type(item["type"]) == dict
            else item["type"]
        )
        return acc

    return reduce(reducer, fields, {})


def fields_to_schema_expanded(fields):
    # if type(fields) != list:
    #     return fields

    def reducer(acc, item):
        acc[item["name"]] = (
            (
                {
                    **{k: v for k, v in item.items() if k not in {"name"}},
                    "type": {
                        "type": "struct",
                        "fields": fields_to_schema_expanded(item["type"]["fields"]),
                    },
                }
                if item["type"]["type"] == "struct"
                else (
                    {
                        **{k: v for k, v in item.items() if k not in {"name"}},
                        "type": {
                            "type": "list",
                            "element": fields_to_schema_expanded(
                                [{"name": "$element", "type": item["type"]["element"]}]
                            )["$element"],
                        },
                    }
                    if item["type"]["type"] == "list"
                    else "UNKNOWN"
                )
            )
            if type(item["type"]) == dict
            else {
                **{k: v for k, v in item.items() if k not in {"name"}},
                "type": "primitive",
                "shape": item["type"],
            }
        )
        return acc

    return reduce(reducer, fields, {})


ECS_SCHEMA = {}


def ecs_subschema_from_fields(fields):
    def reducer(acc, field):
        value, path = deep_find(ECS_SCHEMA, field)
        if field == "@timestamp":
            return acc
        if path is None:
            raise Exception(f"Field {field} not found in ECS schema")
        return merge(acc, deepen({path: value}))

    return reduce(reducer, fields, {})


def is_ecs_field(*keys):
    return deep_find(ECS_SCHEMA, keys)[0] is not None


def schema_to_iceberg(p, extract_ecs_fields=True):
    schema = _to_schema(p[0], is_root=True)
    for e in p[1:]:
        # print(schema)
        schema = merge(schema, _to_schema(e, is_root=True))

    if "@timestamp" in schema:
        v = schema.pop("@timestamp")
        if not extract_ecs_fields:
            schema["ts"] = v

    schema = vrl(
        """
    . = compact(.)
    del(.host.containerized)
    del(.host.os.build)
    del(.host.os.codename)
    del(.cloud.image.id)
    """,
        schema,
    )[0]

    ecs_fields = []
    if extract_ecs_fields:
        paths = [path for path in traverse(schema)]
        for path in paths:
            if is_ecs_field(*path):
                try:
                    v = ensurepath(schema, path)
                    if type(v) == list:
                        v = v[0]
                    del v[path[-1]]
                except:
                    breakpoint()
                ecs_fields.append(".".join(path))

    # print(yaml.dump({"schema": schema, "ecs_field_names": ecs_fields}, sort_keys=False))

    return schema, ecs_fields


with open("fields.ecs.yml") as f:
    d = yaml.load(f, Loader=yaml.FullLoader)
    ECS_SCHEMA = schema_to_iceberg(d[0]["fields"], extract_ecs_fields=False)[0]
    # print(yaml.dump(ecs_schema, sort_keys=False))

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("file", type=str)
    # parser.add_argument('--mode', type=Mode, choices=list(Mode), default=Mode.prod)

    opts = parser.parse_args()

    with open(opts.file) as file:
        p = yaml.load(file, Loader=yaml.FullLoader)

    # res = schema_to_iceberg(p)
    # res = schema_to_iceberg(p[0]["fields"])

    ecs_fields = expand_and_serialize_to_fields(ECS_SCHEMA)
    ecs_fields = [ecs_fields[-1]] + ecs_fields[:-1]  # keep ts at front
    iceberg_ecs_schema = {"type": "struct", "fields": ecs_fields}
    with open("ecs_iceberg_schema.json", "w") as f:
        json.dump(iceberg_ecs_schema, f, indent=2, sort_keys=False)

    with open("ecs_iceberg_schema_compact.yml", "w") as f:
        yaml.dump(ECS_SCHEMA, f, sort_keys=False)

    # print(res)
