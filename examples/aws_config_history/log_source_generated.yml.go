schema:
  fields: []
  ecs_field_names:
  - cloud.account.id
  - cloud.account.name
  - cloud.availability_zone
  - cloud.provider
  - cloud.region
  - cloud.service.name
  - ecs.version
  - event.category
  - event.created
  - event.hash
  - event.kind
  - event.type
  - tags
transform: |-
  # Transform

  # Write your VRL transform script here :)
name: aws_config_history
