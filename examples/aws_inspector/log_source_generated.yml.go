schema:
  ecs_field_names:
  - cloud.account.id
  - cloud.account.name
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
  - event.category
  - event.created
  - event.dataset
  - event.kind
  - event.module
  - event.original
  - event.severity
  - event.type
  - message
  - network.transport
  - related.hash
  - related.ip
  - tags
  - vulnerability.id
  - vulnerability.reference
  - vulnerability.score.base
  - vulnerability.score.version
  - vulnerability.severity
  fields:
  - name: aws
    type:
      type: struct
      fields:
      - name: inspector
        type:
          type: struct
          fields:
          - name: aws_account_id
            type: string
          - name: description
            type: string
          - name: finding_arn
            type: string
          - name: first_observed_at
            type: timestamp
          - name: fix_available
            type: string
          - name: inspector_score
            type: double
          - name: inspector_score_details
            type:
              type: struct
              fields:
              - name: adjusted_cvss
                type:
                  type: struct
                  fields:
                  - name: adjustments
                    type:
                      type: struct
                      fields:
                      - name: metric
                        type: string
                      - name: reason
                        type: string
                  - name: cvss_source
                    type: string
                  - name: score
                    type:
                      type: struct
                      fields:
                      - name: source
                        type: string
                      - name: value
                        type: double
                  - name: scoring_vector
                    type: string
                  - name: version
                    type: string
          - name: last_observed_at
            type: timestamp
          - name: network_reachability_details
            type:
              type: struct
              fields:
              - name: network_path
                type:
                  type: struct
                  fields:
                  - name: steps
                    type:
                      type: struct
                      fields:
                      - name: component
                        type:
                          type: struct
                          fields:
                          - name: id
                            type: string
                          - name: type
                            type: string
              - name: open_port_range
                type:
                  type: struct
                  fields:
                  - name: begin
                    type: long
                  - name: end
                    type: long
              - name: protocol
                type: string
          - name: package_vulnerability_details
            type:
              type: struct
              fields:
              - name: cvss
                type:
                  type: struct
                  fields:
                  - name: base_score
                    type: double
                  - name: scoring_vector
                    type: string
                  - name: source
                    type: string
                  - name: version
                    type: string
              - name: reference_urls
                type: string
              - name: related_vulnerabilities
                type: string
              - name: source
                type:
                  type: struct
                  fields:
                  - name: url
                    type:
                      type: struct
                      fields:
                      - name: domain
                        type: string
                      - name: extension
                        type: string
                      - name: original
                        type: string
                      - name: path
                        type: string
                      - name: query
                        type: string
                      - name: scheme
                        type: string
                  - name: value
                    type: string
              - name: vendor
                type:
                  type: struct
                  fields:
                  - name: created_at
                    type: timestamp
                  - name: severity
                    type: string
                  - name: updated_at
                    type: timestamp
              - name: vulnerability_id
                type: string
              - name: vulnerable_packages
                type:
                  type: struct
                  fields:
                  - name: arch
                    type: string
                  - name: epoch
                    type: long
                  - name: file_path
                    type: string
                  - name: fixed_inversion
                    type: string
                  - name: name
                    type: string
                  - name: package_manager
                    type: string
                  - name: release
                    type: string
                  - name: source_layer_hash
                    type: string
                  - name: version
                    type: string
          - name: remediation
            type:
              type: struct
              fields:
              - name: recommendation
                type:
                  type: struct
                  fields:
                  - name: text
                    type: string
                  - name: url
                    type:
                      type: struct
                      fields:
                      - name: domain
                        type: string
                      - name: extension
                        type: string
                      - name: original
                        type: string
                      - name: path
                        type: string
                      - name: query
                        type: string
                      - name: scheme
                        type: string
          - name: resources
            type:
              type: struct
              fields:
              - name: details
                type:
                  type: struct
                  fields:
                  - name: aws
                    type:
                      type: struct
                      fields:
                      - name: ec2_instance
                        type:
                          type: struct
                          fields:
                          - name: iam_instance_profile_arn
                            type: string
                          - name: image_id
                            type: string
                          - name: ipv4_addresses
                            type: string
                          - name: ipv6_addresses
                            type: string
                          - name: key_name
                            type: string
                          - name: launched_at
                            type: timestamp
                          - name: platform
                            type: string
                          - name: subnet_id
                            type: string
                          - name: type
                            type: string
                          - name: vpc_id
                            type: string
                      - name: ecr_container_image
                        type:
                          type: struct
                          fields:
                          - name: architecture
                            type: string
                          - name: author
                            type: string
                          - name: image
                            type:
                              type: struct
                              fields:
                              - name: hash
                                type: string
                              - name: tags
                                type: string
                          - name: platform
                            type: string
                          - name: pushed_at
                            type: timestamp
                          - name: registry
                            type: string
                          - name: repository_name
                            type: string
              - name: id
                type: string
              - name: partition
                type: string
              - name: region
                type: string
              - name: tags
                type: string
              - name: type
                type: string
          - name: severity
            type: string
          - name: status
            type: string
          - name: title
            type: string
          - name: type
            type: string
          - name: updated_at
            type: timestamp
transform: |-
  # Transform

  # Write your VRL transform script here :)
name: aws_inspector
