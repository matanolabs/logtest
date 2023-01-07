schema:
  ecs_field_names:
  - cloud.account.id
  - cloud.availability_zone
  - cloud.instance.id
  - cloud.instance.name
  - cloud.machine.type
  - cloud.project.id
  - cloud.provider
  - cloud.region
  - container.id
  - container.image.name
  - container.labels
  - container.name
  - ecs.version
  - event.created
  - event.dataset
  - event.module
  - event.original
  - host.architecture
  - host.domain
  - host.hostname
  - host.id
  - host.ip
  - host.mac
  - host.name
  - host.os.family
  - host.os.kernel
  - host.os.name
  - host.os.platform
  - host.os.version
  - host.type
  - tags
  fields:
  - name: cisco_duo
    type:
      type: struct
      fields:
      - name: summary
        type:
          type: struct
          fields:
          - name: admin_count
            type: int
          - name: integration_count
            type: int
          - name: telephony_credits_remaining
            type: int
          - name: user_count
            type: int
transform: "\n\n.ecs.version = \"8.5.0\"\n\n.ts = .{_ingest.timestamp}\n\n.event.original\
  \ = del(.message)\n\n           \nunhandled = true                       \n## op:\
  \ json                            \n# {\n#   \"field\": \"event.original\",\n# \
  \  \"target_field\": \"json\",\n#   \"ignore_failure\": true\n# }              \
  \     \n# script                                \n#                        \n\n\
  .cisco_duo.summary.admin_count = del(.json.response.admin_count)\n\n.cisco_duo.summary.integration_count\
  \ = del(.json.response.integration_count)\n\n.cisco_duo.summary.telephony_credits_remaining\
  \ = del(.json.response.telephony_credits_remaining)\n\n.cisco_duo.summary.user_count\
  \ = del(.json.response.user_count)\n\ndel(.json)"
name: duo_summary
