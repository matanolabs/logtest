from modulefinder import Module
import yaml

from rich import print
from pathlib import Path
import json
from collections import defaultdict
from typing import Iterable
import pyperclip
import re
import sys

from ecs_schema_to_iceberg import ecs_to_iceberg_type
from rich.console import Console

console = Console()

from argparse import ArgumentParser
from enum import Enum


class Mode(Enum):
    prod = "prod"
    vrlweb = "vrlweb"

    def __str__(self):
        return self.value


def flatten(items):
    """Yield items from any nested iterable; see Reference."""
    for x in items:
        if isinstance(x, Iterable) and not isinstance(x, (str, bytes)):
            for sub_x in flatten(x):
                yield sub_x
        else:
            yield x


blacklist_obj = [
    {
        "field": "message",
        "target_field": "event.original",
        "if": "ctx.event?.original == null",
        "description": "Renames the original `message` field to `event.original` to store a copy of the original message. The `event.original` field is not touched if the document already has one; it may happen when Logstash sends the document.",
    },
    {
        "field": "message",
        "ignore_missing": True,
        "if": "ctx.event?.original != null",
        "description": "The `message` field is no longer required if the document has an `event.original` field.",
    },
    # {'if': "ctx['@timestamp'] != null", 'field': 'event.created', 'copy_from': '@timestamp'},
    {"field": "event.original", "target_field": "json"},
    {"field": "ecs.version", "value": "8.0.0"},
    {"field": "ecs.version", "value": "8.4.0"},
]
blacklist_op = ["pipeline", "geoip"]

is_clean = defaultdict(lambda: True)
renamed_fields = set()


### Implemented Operations ###


def rename_to_vrl(obj):
    target_field = obj["target_field"]
    s = f".{target_field} = del(.{obj['field']})"

    if target_field in renamed_fields:
        s += f" || .{target_field}"
    else:
        renamed_fields.add(obj["target_field"])

    return s + "\n"

def drop_to_vrl(obj):
    return "abort\n"

# op: split
# {"field": "apache.access.remote_addresses", "separator": "\"?,\\s*", "ignore_missing": true}
def split_to_vrl(obj):
    field = obj["field"]
    separator = obj["separator"]

    ignore_missing = obj.get("ignore_missing", False)

    if ignore_missing:
        return f"\
if .{field} != null {{                         \n\
  .{field} = split!(.{field}, r'{separator}')  \n\
}}                                             \n\
"
    else:
        return f"\
.{field} = split!(.{field}, r'{separator}')  \n\
"
def dot_expander_to_vrl(obj):
    if "path" not in obj:
        return ""
    path = obj["path"]
    field = obj["field"]
    ignore_failure = obj.get("ignore_failure", False)

    if not ignore_failure:
        return f'\
.{path} = set!(.{path}, split("{field}", "."), .{path}."{field}")\n\
del(.{path}."{field}")\n\n\
'
    else:
# if err == null {{ \n\
# }}\n\n
        return f'\
.{path}, err = set(.{path}, split("{field}", "."), .{path}."{field}")\n\
del(.{path}."{field}")\n\n\
'


def ua_to_vrl(obj, *, mode):
    if "on_failure" not in obj:
        s = f".{obj['target_field']} = parse_user_agent!(del(.{obj['field']}))"
    else:
        processors = obj["on_failure"]
        assert len(processors) == 1

        op, subobj = list(processors[0].items())[0]
        func = globals()[f"{op}_to_vrl"]  # LOL
        expr = func(subobj)

        not_empty_check = "ua != {}" if mode == Mode.vrlweb else "!is_empty(ua)"
        s = f"                                                           \n\
ua, err = parse_user_agent(.{obj['field']})                              \n\
ua = compact(ua)                                                         \n\
if {not_empty_check} && err == null {{                                   \n\
    # TODO (parse fields)                                                \n\
    .user_agent = ua                                                     \n\
    {expr.rstrip()}                                                      \n\
}} else {{                                                               \n\
    {expr.rstrip()}                                                      \n\
}}"

    return s + "\n"


def append_to_vrl(obj, *, mode):
    if type(obj["value"]) == str and obj["value"][:2] == "{{" and obj["value"][-2:] == "}}":
        obj["value"] = "." + obj["value"][2:-2]
    else:
        obj["value"] = f"\"{obj['value']}\""
    value = obj["value"]
    field = obj["field"]

    if not field.startswith("related") and field not in is_clean:
        is_clean[field] = True

    push = "push!"
    if is_clean[field]:
        push = "push"
    else:
        if mode == Mode.vrlweb:
            is_clean[field] = True

    ret = f".{field} = {push}(.{field}, {value}) \n"
    #     if value.startswith("."):
    #         ret =  f"\
    # if {value} != null {{   \n\
    #     {ret}                \n\
    # }}                      \n\
    # "
    return ret


def set_to_vrl(obj):
    if "value" not in obj:
        obj["value"] = "{{" + obj["copy_from"] + "}}"

    if type(obj["value"]) == str and obj["value"][:2] == "{{" and obj["value"][-2:] == "}}":
        obj["value"] = "." + obj["value"][2:-2]
    else:
        obj["value"] = f"\"{obj['value']}\""
    return f".{obj['field']} = {obj['value']}\n"

iceberg_to_vrl_type = {
    "int": "int",
    "long": "int",
    "double": "float",
    "float": "float",
    "string": "string",
    "boolean": "bool",
}
def convert_to_vrl(obj):
    target_field = obj.get("target_field", obj["field"])
    typename = obj["type"]
    # try:
    vrltype = iceberg_to_vrl_type[ecs_to_iceberg_type({"type":typename})]
    # except Exception as e:
    #     print(e)
    #     vrltype = typename

    return f"\
if .{obj['field']} != null {{                       \n\
    .{target_field} = to_{vrltype}!(.{obj['field']}) \n\
}}                                                  \n\
"

def remove_to_vrl(obj):
    fields = [obj["field"]] if type(obj["field"]) != list else obj["field"]
    s = "\n".join([f"del(.{field})" for field in fields])
    s += "\n"
    return s


def date_to_vrl(obj):
    if "target_field" not in obj:
        obj["target_field"] = "@timestamp"  # obj["field"]
    field = obj["field"]

    # if is_integer(.{field}) || is_float(.{field}) && .{field} > 100000000000 {{  \n\
    # .{field} = .{field} / 1000                                                 \n\
    # }}                                                                           \n\
# milliseconds
    return f"\
if .{obj['field']} != null {{                                               \n\
  .{obj['target_field']} = to_timestamp!(.{obj['field']}, \"seconds\") \n\
}}\n"


def grok_to_vrl(obj):
    return f"                                                                \n\
_grokked, err = parse_groks(.{obj['field']}, {json.dumps(obj['patterns'])})  \n\
if err == null {{                                                            \n\
    . |= _grokked                                                            \n\
}}                                                                           \n\
"


#############################


def painful(s, *, mode):
    def without_useless_quotes(match):
        group = eval(match.group(1)).replace("@timestamp", "ts")
        assert type(group) == str
        if any(not c.isalnum() for c in group):
            group = f'"{group}"'

        return "." + group

    if_s = (
        s.replace("?", "").replace("ctx[", "[").replace("ctx.", ".").replace("'", '"').replace("; ", "\n").replace(";\n", "\n")
    )
    try:
        if_s = re.sub(r"\[(.*)\]", without_useless_quotes, if_s)
    except:
        pass

    if_s = re.sub(
        r"([.\w]*)\.isEmpty\(\)",
        r"is_empty(\1)" if mode == Mode.prod else r'\1 == "" || \1 == [] || \1 == {}',
        if_s,
    )  # a.isEmpty() => is_empty(a)
    if_s = re.sub(
        r"([.\w]*)\.contains\((.*)\)", r"contains(\1, \2)", if_s
    )  # a.contains(x) => contains(a, x)

    return if_s


def pipeline_to_vrl(pipeline, *, mode):
    global is_clean, renamed_fields
    vrl_template = ""

    # breakpoint()
    for processor in pipeline["processors"]:
        op, obj = list(processor.items())[0]
        if obj in blacklist_obj:
            continue
        if op in blacklist_op:
            continue
        if obj.get("field") == "event.original" and obj.get("target_field") == "_temp_":
            continue

        the_if = obj.pop("if") if "if" in obj else None

        block = ""
        if op == "rename":
            block += rename_to_vrl(obj)
        elif op == "user_agent":
            if "target_field" not in obj:
                obj["target_field"] = "user_agent"
            block += ua_to_vrl(obj, mode=mode)
        elif op == "append":
            block += append_to_vrl(obj, mode=mode)
        elif op == "set":
            block += set_to_vrl(obj)
        elif op == "remove":
            block += remove_to_vrl(obj)
        elif op == "split":
            block += split_to_vrl(obj)
        elif op == "drop":
            block += drop_to_vrl(obj)
        elif op == "date":
            block += date_to_vrl(obj)
        elif op == "convert":
            block += convert_to_vrl(obj)
        elif op == "grok":
            block += grok_to_vrl(obj)
            prev = {k: False for k, v in is_clean.items()}
            is_clean = defaultdict(lambda: False)
            is_clean.update(prev)  # LOL
        elif op == "dot_expander":
            block += dot_expander_to_vrl(obj)
        else:
            # console.print(f"{op}", style="bold yellow")
            if obj.get("lang") == "painless":
                dsc = obj.get("description")
                if (
                    dsc
                    and ("null" in dsc)
                    and ("drops" in dsc.lower() or "removes".lower() in dsc)
                ):
                    continue

                source = painful(obj["source"], mode=mode)

                if all(x in source for x in ("handleMap", "removeIf", "null")):
                    continue

                source_comment = "# " + source.replace("\n", "\n# ")
                block += f"            \n\
script = true                         \n\
## op: {op}                            \n\
{source_comment}                        \n"
                # obj["source"] = obj["source"].split("\n")
                # obj["source"] = list(flatten([o.split("; ") for o in obj["source"]]))
            else:
                source_comment = ""
                if "source" in obj:
                    source_comment = painful(obj["source"], mode=mode).replace("\n", "\n# ")
                    del obj["source"]
                script_comment = painful(json.dumps(obj, indent=2).replace("\n", "\n# "), mode=mode)
                if op == "community_id":
                    block += "# TODO(): add community network id\n"
                else:
                    block += f"           \n\
unhandled = true                       \n\
## op: {op}                            \n\
# {script_comment}                   \n\
# script                                \n\
# {source_comment}                       \n"
                # print(obj)

            # print("\n")

        if block and the_if:
            if_s = painful(the_if, mode=mode)

            if_s = if_s.replace("\n", "\n    ").rstrip("    ")
            newline = "\n"
            tab = "\t"
            if not (op == "set" and if_s == f".{obj.get('copy_from')} != null"):
                block = f"\
if {if_s} {{ \n\
    {block.replace(newline, newline + tab).rstrip(tab)}\
}}\n\n\
    "
        if block:
            block += "\n"

        # print(block)
        if "preserve_original_event" in block:
            continue
        if block == ".event.original = del(.message)":
            continue

        vrl_template += block

    # console.print(
    #     f"\n\n\n######## COMPILED VRL TEMPLATE ########\n", style="bold green"
    # )
    vrl_template = (
        vrl_template.replace("@timestamp", ".ts")
        .replace("..", ".")
        .replace("\n\n\n", "\n\n")
        .replace("._temp_", ".json")
        .rstrip("\n")
    )
    vrl_template = (
#         """
# .related.user = []
# .related.hash = []
# .related.ip = []\n
# """ +
        "\n".join([f".{k} = []" for k in is_clean if not k.startswith("related")])
        + "\n\n"
        + vrl_template
        # + "\n. = compact(.)"
    )
    # pyperclip.copy(vrl_template)
    # print(vrl_template)
    return vrl_template

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("file", type=str)
    parser.add_argument("--mode", type=Mode, choices=list(Mode), default=Mode.prod)

    opts = parser.parse_args()

    with open(Path(opts.file)) as f:
        pipeline = yaml.safe_load(f)
        pipeline_to_vrl(pipeline, mode=opts.mode)
