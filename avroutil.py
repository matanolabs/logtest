from avro.schema import (
    Schema,
    Field,
    RecordSchema,
    PrimitiveSchema,
    LogicalSchema,
    ArraySchema,
    UnionSchema,
)

PRIMITIVE_FIELD_TYPE_MAPPING_ICEBERG_TO_AVRO = {
    "boolean": "boolean",
    "binary": "bytes",
    "double": "double",
    "float": "float",
    "integer": "int",
    "long": "long",
    "string": "string",
    # "timestamp": "long",
}

# LOGICAL_FIELD_TYPE_MAPPING = {
#     "timestamp": ("timestamp-micros", "long")
# }


def iceberg_to_avro_schema(schema, *, root=False, path="root"):
    if type(schema) == dict:
        schema_to_field = lambda s, p: Field(
            s.to_json()["type"], p, has_default=True, default="null"
        )
        avro_schema = RecordSchema(
            path,
            None,
            fields=[
                schema_to_field(
                    iceberg_to_avro_schema(v, path=f"{path}.{k}"), f"{path}.{k}"
                )
                for k, v in schema.items()
            ],
        )
    elif type(schema) == list:
        avro_schema = ArraySchema(
            items=iceberg_to_avro_schema(schema[0], path=f"{path}.items").to_json()[
                "type"
            ],
        )
    elif schema == "timestamp":
        avro_schema = TimestampMicrosSchema()
    else:
        avro_schema = PrimitiveSchema(
            PRIMITIVE_FIELD_TYPE_MAPPING_ICEBERG_TO_AVRO[schema],
        )

    if not root:
        return UnionSchema([PrimitiveSchema("null"), avro_schema])
