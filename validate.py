from sys import float_info
from avro.schema import (
    RecordSchema,
    PrimitiveSchema,
    LogicalSchema,
    ArraySchema,
    UnionSchema,
)
from avro.name import Names
import avro_validator
from avro_validator.schema import Schema
import json
import pretty_errors

from rich.console import Console
import rich
from rich.panel import Panel

from runner import vrl

error_console = Console(stderr=True, style="bold red")


PRIMITIVE_FIELD_TYPE_MAPPING_ICEBERG_TO_AVRO = {
    "boolean": "boolean",
    "binary": "bytes",
    "double": "double",
    "float": "float",
    "int": "int",
    "long": "long",
    "string": "string",
    # "timestamp": "long",
}

PRIMITIVE_FIELD_TYPE_MAPPING_ICEBERG_TO_PY_TYPES = {
    "boolean": (bool,),
    "binary": (bytes,),
    "double": (int, float,),
    "float": (int, float,),
    "int": (int,),
    "long": (int, float),
    "string": (str,),
    "timestamp": (float, int,),
}

# LOGICAL_FIELD_TYPE_MAPPING = {
#     "timestamp": ("timestamp-micros", "long")
# }


def iceberg_pretty_validator(datum, schema, *, path=""):
    root = not path
    # if root:
    #     rich.print("[bold white]Validating:")
    #     rich.print(datum, "\n")

    print_path = (
        f"[bold white]field [bold cyan]{path}[reset]"
        if path
        else "[bold white]root record[reset]"
    )
    if type(schema) == dict:
        if datum is not None and type(datum) != dict:
            error_console.print(
                f"[bold red]Validation Error[reset]: {print_path} should be a [green]dict[reset]: not [red]{type(datum).__name__}"
            )
            rich.print(
                Panel.fit(
                    f"{json.dumps(datum, indent=2)}",
                    title=f"{print_path.replace('field ', '')}",
                )
            )
            return False

        for k in set(datum.keys() if datum else {}) - set(schema.keys()):
            if path == "" and k == "ts":
                iceberg_pretty_validator(datum[k], "timestamp", path=".ts")
                continue

            v = datum[k]
            if type(v) == dict:
                extra_keys = vrl("""
                keys = []
                for_each(flatten!(.)) -> |k, v| {{
                    keys = push(keys, k)
                }}
                keys
                """, datum[k])[1]
                for ex_k in extra_keys:
                    error_console.print(f"[bold yellow]Warning: Extra key in datum: [reset][bold]: {path}.{k}.{ex_k}")
            else:
                error_console.print(f"[bold yellow]Warning: Extra key in datum: [reset][bold]: {path}.{k}")

        return all(
            [
                iceberg_pretty_validator(
                    datum.get(k) if datum else None, v, path=f"{path}.{k}"
                )
                for k, v in schema.items()
            ]
        )
    elif type(schema) == list:
        if datum and type(datum) != list:
            error_console.print(
                f"[bold red]Validation Error[reset]: {print_path} should be a [green]list[reset]: not [red]{type(datum).__name__}"
            )
            rich.print(
                Panel.fit(
                    f"{json.dumps(datum, indent=2)}",
                    title=f"{print_path.replace('field ', '')}",
                )
            )
            return False
        return all(
            [
                iceberg_pretty_validator(item, schema[0], path=f"{path}.items[{i}]")
                for i, item in enumerate(datum or [])
            ]
        )
    elif schema == "timestamp":
        if (
            datum
            and not (
                type(datum) == str
                and (
                    datum.endswith("Z") or datum.startswith("20") or datum.startswith("19")
                )
            )
        ):
            error_console.print(
                f"[bold red]Validation Error[reset]: {print_path} should be a [green]timestamp (long)[reset]: not [red]{type(datum).__name__}"
            )
            rich.print(
                Panel.fit(
                    f"{json.dumps(datum, indent=2)}",
                    title=f"{print_path.replace('field ', '')}",
                )
            )
            return False
    else:
        if (
            datum
            and type(datum)
            not in PRIMITIVE_FIELD_TYPE_MAPPING_ICEBERG_TO_PY_TYPES[schema]
        ):
            pytypes = " | ".join(
                [
                    t.__name__
                    for t in PRIMITIVE_FIELD_TYPE_MAPPING_ICEBERG_TO_PY_TYPES[schema]
                ]
            )
            error_console.print(
                f"[bold red]Validation Error[reset]: {print_path} should be a [green]{pytypes}[reset]: not [red]{type(datum).__name__}"
            )
            rich.print(
                Panel.fit(
                    f"{json.dumps(datum, indent=2)}",
                    title=f"{print_path.replace('field ', '')}",
                )
            )
            return False
    return True


def iceberg_to_avro_schema(schema, *, root=False, path="root"):
    if type(schema) == dict:

        def schema_to_field(s, k):
            info = s.to_json()

            return {"name": k, "type": info, "default": "null"}
            # return Field(info, p, has_default = True, default = "null")

        avro_schema = RecordSchema(
            path,
            "dddjjd",
            names=Names(),
            fields=[
                schema_to_field(iceberg_to_avro_schema(v, path=f"{path}.{k}"), f"{k}")
                for k, v in schema.items()
            ],
        )
    elif type(schema) == list:
        avro_schema = ArraySchema(
            items=iceberg_to_avro_schema(schema[0], path=f"{path}.items").to_json(),
        )
    elif schema == "timestamp":
        avro_schema = TimestampMicrosSchema()
    else:
        avro_schema = PrimitiveSchema(
            PRIMITIVE_FIELD_TYPE_MAPPING_ICEBERG_TO_AVRO[schema],
        )

    if not root:
        return UnionSchema(
            [PrimitiveSchema("null").to_json(), avro_schema.to_json()], names=Names()
        )
    return avro_schema


def validate_iceberg_schema(schema, test_records):
    # avro_schema = iceberg_to_avro_schema(schema, root=True)
    # avro_schema_json = avro_schema.to_json()
    # validator = Schema(json.dumps(avro_schema_json)).parse()
    results = []
    for record in test_records:
        # avro_validate_result = validator.validate(record)
        # if avro_validate_result:
        #     assert avro_validate_result == iceberg_pretty_validator(record, schema)
        res = iceberg_pretty_validator(record, schema)
        if not res:
            rich.print("\n❌ [bold white]Object failed validation:")
            rich.print(record, "\n")
        results.append(res)
    return all(results)


# validate_iceberg_schema(
#     {"john": {"blake": "integer", "cherry": "string"}},
#     [
#         {"john": {"blake": 2}},
#         {"john": {"blake": 2.0}},
#         {"john": {"blake": "2", "cherry": 1, "hane": 1}},
#         {"john": {"blake": {"john": {"blake": "2"}}}},
#     ],
# )
