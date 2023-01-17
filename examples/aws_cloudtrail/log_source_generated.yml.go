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
  - error.message
  - event.action
  - event.category
  - event.created
  - event.dataset
  - event.id
  - event.ingested
  - event.kind
  - event.module
  - event.original
  - event.outcome
  - event.provider
  - event.type
  - file.hash.md5
  - file.hash.sha1
  - file.hash.sha256
  - file.hash.sha512
  - file.path
  - group.id
  - group.name
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
  - related.hash
  - related.user
  - source.address
  - source.as.number
  - source.as.organization.name
  - source.geo.city_name
  - source.geo.continent_name
  - source.geo.country_iso_code
  - source.geo.country_name
  - source.geo.location.lat
  - source.geo.location.lon
  - source.geo.region_iso_code
  - source.geo.region_name
  - source.ip
  - tags
  - user.changes.name
  - user.id
  - user.name
  - user.target.id
  - user.target.name
  - user_agent.device.name
  - user_agent.name
  - user_agent.original
  - user_agent.os.full
  - user_agent.os.name
  - user_agent.os.version
  - user_agent.version
  fields:
  - name: aws
    type:
      type: struct
      fields:
      - name: cloudtrail
        type:
          type: struct
          fields:
          - name: additional_eventdata
            type: string
          - name: api_version
            type: string
          - name: console_login
            type:
              type: struct
              fields:
              - name: additional_eventdata
                type:
                  type: struct
                  fields:
                  - name: login_to
                    type: string
                  - name: mfa_used
                    type: boolean
                  - name: mobile_version
                    type: boolean
          - name: digest
            type:
              type: struct
              fields:
              - name: end_time
                type: timestamp
              - name: log_files
                type:
                  type: list
                  element: string
              - name: newest_event_time
                type: timestamp
              - name: oldest_event_time
                type: timestamp
              - name: previous_hash_algorithm
                type: string
              - name: previous_s3_bucket
                type: string
              - name: public_key_fingerprint
                type: string
              - name: s3_bucket
                type: string
              - name: s3_object
                type: string
              - name: signature_algorithm
                type: string
              - name: start_time
                type: timestamp
          - name: error_code
            type: string
          - name: error_message
            type: string
          - name: event_category
            type: string
          - name: event_type
            type: string
          - name: event_version
            type: string
          - name: flattened
            type:
              type: struct
              fields:
              - name: additional_eventdata
                type: string
              - name: request_parameters
                type: string
              - name: response_elements
                type: string
              - name: service_event_details
                type: string
              - name: digest
                type: string
              - name: insight_details
                type: string
          - name: insight_details
            type: string
          - name: management_event
            type: string
          - name: read_only
            type: boolean
          - name: recipient_account_id
            type: string
          - name: request_id
            type: string
          - name: request_parameters
            type: string
          - name: resources
            type:
              type: struct
              fields:
              - name: account_id
                type: string
              - name: arn
                type: string
              - name: type
                type: string
          - name: response_elements
            type: string
          - name: service_event_details
            type: string
          - name: shared_event_id
            type: string
          - name: user_identity
            type:
              type: struct
              fields:
              - name: access_key_id
                type: string
              - name: arn
                type: string
              - name: invoked_by
                type: string
              - name: session_context
                type:
                  type: struct
                  fields:
                  - name: creation_date
                    type: timestamp
                  - name: mfa_authenticated
                    type: string
                  - name: session_issuer
                    type:
                      type: struct
                      fields:
                      - name: account_id
                        type: string
                      - name: arn
                        type: string
                      - name: principal_id
                        type: string
                      - name: type
                        type: string
              - name: type
                type: string
          - name: vpc_endpoint_id
            type: string
transform: "\n\nif .ts != null { \n    .event.created = .ts\n}\n\n    \nif .json.eventTime\
  \ != null {                                               \n  .ts = to_timestamp!(.json.eventTime,\
  \ \"seconds\") \n}\n\n.aws.cloudtrail.event_version = del(.json.eventVersion)\n\n\
  .aws.cloudtrail.user_identity.type = del(.json.userIdentity.type)\n\nif .json.userIdentity.userName\
  \ != null { \n    .related.user = push(.related.user, .json.userIdentity.userName)\
  \ \n}\n\n    \n.user.name = del(.json.userIdentity.userName)\n\n.user.id = del(.json.userIdentity.principalId)\n\
  \n.aws.cloudtrail.user_identity.arn = del(.json.userIdentity.arn)\n\n.cloud.account.id\
  \ = del(.json.userIdentity.accountId)\n\n.aws.cloudtrail.user_identity.access_key_id\
  \ = del(.json.userIdentity.accessKeyId)\n\n.aws.cloudtrail.user_identity.session_context.mfa_authenticated\
  \ = del(.json.userIdentity.sessionContext.attributes.mfaAuthenticated)\n\nif .json.userIdentity.sessionContext.attributes.creationDate\
  \ != null {                                               \n  .aws.cloudtrail.user_identity.session_context.creation_date\
  \ = to_timestamp!(.json.userIdentity.sessionContext.attributes.creationDate, \"\
  seconds\") \n}\n\n.aws.cloudtrail.user_identity.session_context.session_issuer.type\
  \ = del(.json.userIdentity.sessionContext.sessionIssuer.type)\n\n.user.name = del(.json.userIdentity.sessionContext.sessionIssuer.userName)\
  \ || .user.name\n\n.aws.cloudtrail.user_identity.session_context.session_issuer.principal_id\
  \ = del(.json.userIdentity.sessionContext.sessionIssuer.principalId)\n\n.aws.cloudtrail.user_identity.session_context.session_issuer.arn\
  \ = del(.json.userIdentity.sessionContext.sessionIssuer.arn)\n\n.aws.cloudtrail.user_identity.session_context.session_issuer.account_id\
  \ = del(.json.userIdentity.sessionContext.sessionIssuer.accountId)\n\n.aws.cloudtrail.user_identity.invoked_by\
  \ = del(.json.userIdentity.invokedBy)\n\n.event.provider = del(.json.eventSource)\n\
  \n.event.action = .json.eventName\n\n.aws.cloudtrail.event_category = del(.json.eventCategory)\n\
  \n.cloud.region = .json.awsRegion\n\n.source.address = del(.json.sourceIPAddress)\n\
  \n                                                                \n_grokked, err\
  \ = parse_groks(.source.address, [\"^%{IP:source.ip}$\"])  \nif err == null {  \
  \                                                          \n    . |= _grokked \
  \                                                           \n}                \
  \                                                           \n\n.source.as.number\
  \ = del(.source.as.asn)\n\n.source.as.organization.name = del(.source.as.organization_name)\n\
  \n                                                           \nua, err = parse_user_agent(.json.userAgent)\
  \                              \nua = compact(ua)                              \
  \                           \nif !is_empty(ua) && err == null {                \
  \                   \n    # TODO (parse fields)                                \
  \                \n    .user_agent = ua                                        \
  \             \n    .user_agent.original = del(.json.userAgent)                \
  \                                      \n} else {                              \
  \                                 \n    .user_agent.original = del(.json.userAgent)\
  \                                                      \n}\n\n.aws.cloudtrail.error_code\
  \ = del(.json.errorCode)\n\n.aws.cloudtrail.error_message = del(.json.errorMessage)\n\
  \n            \nscript = true                         \n## op: script          \
  \                  \n# if (.aws.cloudtrail.flattened == null) {\n#     Map map =\
  \ new HashMap()\n#     .aws.cloudtrail.put(\"flattened\", map)\n#   }\n# if (.json.requestParameters\
  \ != null) {\n#   .aws.cloudtrail.request_parameters = .json.requestParameters.toString()\n\
  #   if (.aws.cloudtrail.request_parameters.length() < 32766) {\n#     .aws.cloudtrail.flattened.put(\"\
  request_parameters\", .json.requestParameters)\n#   }\n# }\n# if (.json.responseElements\
  \ != null) {\n#   .aws.cloudtrail.response_elements = .json.responseElements.toString()\n\
  #   if (.aws.cloudtrail.response_elements.length() < 32766) {\n#     .aws.cloudtrail.flattened.put(\"\
  response_elements\", .json.responseElements)\n#   }\n# }\n# if (.json.additionalEventData\
  \ != null) {\n#   .aws.cloudtrail.additional_eventdata = .json.additionalEventData.toString()\n\
  #   if (.aws.cloudtrail.additional_eventdata.length() < 32766) {\n#     .aws.cloudtrail.flattened.put(\"\
  additional_eventdata\", .json.additionalEventData)\n#   }\n# }\n# if (.json.serviceEventDetails\
  \ != null) {\n#   .aws.cloudtrail.service_event_details = .json.serviceEventDetails.toString()\n\
  #   if (.aws.cloudtrail.service_event_details.length() < 32766) {\n#     .aws.cloudtrail.flattened.put(\"\
  service_event_details\", .json.serviceEventDetails)\n#   }\n# }\n#             \
  \            \n\n.aws.cloudtrail.request_id = del(.json.requestID)\n\n.event.id\
  \ = del(.json.eventID)\n\n.aws.cloudtrail.event_type = del(.json.eventType)\n\n\
  .aws.cloudtrail.api_version = del(.json.apiVersion)\n\n.aws.cloudtrail.management_event\
  \ = del(.json.managementEvent)\n\n.aws.cloudtrail.read_only = del(.json.readOnly)\n\
  \n.aws.cloudtrail.resources.arn = del(.json.resources.ARN)\n\n.aws.cloudtrail.resources.account_id\
  \ = del(.json.resources.accountId)\n\n.aws.cloudtrail.resources.type = del(.json.resources.type)\n\
  \n.aws.cloudtrail.recipient_account_id = del(.json.recipientAccountId)\n\n.aws.cloudtrail.shared_event_id\
  \ = del(.json.sharedEventId)\n\n.aws.cloudtrail.vpc_endpoint_id = del(.json.vpcEndpointId)\n\
  \nif .aws.cloudtrail.flattened.request_parameters.userName != null { \n    .related.user\
  \ = push!(.related.user, .aws.cloudtrail.flattened.request_parameters.userName)\
  \ \n}\n\n    \nif .aws.cloudtrail.flattened.request_parameters.newUserName != null\
  \ { \n    .related.user = push!(.related.user, .aws.cloudtrail.flattened.request_parameters.newUserName)\
  \ \n}\n\n    \n            \nscript = true                         \n## op: script\
  \                            \n# if (.json.eventName != \"ConsoleLogin\") {\n# \
  \  return\n# } Map aed_map = new HashMap()\n# if (.aws.cloudtrail.flattened.additional_eventdata.MobileVersion\
  \ != null) {\n#   if (.aws.cloudtrail.flattened.additional_eventdata.MobileVersion\
  \ == \"No\") {\n#     aed_map.put(\"mobile_version\", false)\n#   } else {\n#  \
  \   aed_map.put(\"mobile_version\", true)\n#   }\n# } if (.aws.cloudtrail.flattened.additional_eventdata.LoginTo\
  \ != null) {\n#   aed_map.put(\"login_to\", .aws.cloudtrail.flattened.additional_eventdata.LoginTo)\n\
  # } if (.aws.cloudtrail.flattened.additional_eventdata.MFAUsed != null) {\n#   if\
  \ (.aws.cloudtrail.flattened.additional_eventdata.MFAUsed == \"No\") {\n#     aed_map.put(\"\
  mfa_used\", false)\n#   } else {\n#     aed_map.put(\"mfa_used\", true)\n#   }\n\
  # } if (aed_map.size() > 0) {\n#   Map cl_map = new HashMap()\n#   cl_map.put(\"\
  additional_eventdata\", aed_map)\n#   .aws.cloudtrail.put(\"console_login\", cl_map)\n\
  # }                        \n\n            \nscript = true                     \
  \    \n## op: script                            \n# .event.kind = \"event\"\n# .event.type\
  \ = \"info\"\n# if (.aws.cloudtrail.error_code != null || .aws.cloudtrail.error_message\
  \ != null) {\n#     .event.outcome = \"failure\"\n# } else {\n#     .event.outcome\
  \ = \"success\"\n# }\n# if (.event.action == null) {\n#     return\n# }\n# if (.event.action\
  \ == \"ConsoleLogin\" && .aws.cloudtrail.flattened.response_elements.ConsoleLogin\
  \ != null) {\n#     .event.outcome = Processors.lowercase(.aws.cloudtrail.flattened.response_elements.ConsoleLogin)\n\
  # }\n# if (params.get(.event.action) == null) {\n#     return\n# }\n# def hm = new\
  \ HashMap(params.get(.event.action))\n# hm.forEach((k, v) -> .event[k] = v);   \
  \                     \n\n.cloud.account.id = del(.json.awsAccountId) || .cloud.account.id\n\
  \n.file.path = del(.json.digestS3Object)\n\nif .json.previousDigestHashAlgorithm\
  \ != null && .json.previousDigestHashAlgorithm == \"SHA-256\" { \n    .file.hash.sha256\
  \ = del(.json.previousDigestSignature)\n}\n\n    \nif .file.hash.sha256 != null\
  \ { \n    .related.hash = push!(.related.hash, .file.hash.sha256) \n}\n\n    \n\
  .aws.cloudtrail.digest.log_files = del(.json.logFiles)\n\nif .json.digestStartTime\
  \ != null {                                               \n  .aws.cloudtrail.digest.start_time\
  \ = to_timestamp!(.json.digestStartTime, \"seconds\") \n}\n\nif .json.digestEndTime\
  \ != null {                                               \n  .ts = to_timestamp!(.json.digestEndTime,\
  \ \"seconds\") \n}\n\nif .json.digestEndTime != null {                         \
  \                      \n  .aws.cloudtrail.digest.end_time = to_timestamp!(.json.digestEndTime,\
  \ \"seconds\") \n}\n\n.aws.cloudtrail.digest.s3_bucket = del(.json.digestS3Bucket)\n\
  \nif .json.newestEventTime != null {                                           \
  \    \n  .aws.cloudtrail.digest.newest_event_time = to_timestamp!(.json.newestEventTime,\
  \ \"seconds\") \n}\n\nif .json.oldestEventTime != null {                       \
  \                        \n  .aws.cloudtrail.digest.oldest_event_time = to_timestamp!(.json.oldestEventTime,\
  \ \"seconds\") \n}\n\n.aws.cloudtrail.digest.previous_s3_bucket = del(.json.previousDigestS3Bucket)\n\
  \n.aws.cloudtrail.digest.previous_hash_algorithm = del(.json.previousDigestHashAlgorithm)\n\
  \n.aws.cloudtrail.digest.public_key_fingerprint = del(.json.publicKeyFingerprint)\n\
  \n.aws.cloudtrail.digest.signature_algorithm = del(.json.digestSignatureAlgorithm)\n\
  \n.aws.cloudtrail.insight_details = del(.json.insightDetails)\n\n.group.id = .aws.cloudtrail.flattened.response_elements.group.groupId\n\
  \n.user.target.id = .aws.cloudtrail.flattened.response_elements.user.userId\n\n\
  .user.changes.name = .aws.cloudtrail.flattened.request_parameters.newUserName\n\n\
  .group.name = .aws.cloudtrail.flattened.request_parameters.groupName\n\n.user.target.name\
  \ = .aws.cloudtrail.flattened.request_parameters.userName\n\n.aws.cloudtrail.flattened.digest\
  \ = del(.aws.cloudtrail.digest)\n\n.aws.cloudtrail.flattened.insight_details = del(.aws.cloudtrail.insight_details)\n\
  \ndel(.json)"
name: aws_cloudtrail
