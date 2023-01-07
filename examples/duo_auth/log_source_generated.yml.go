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
  - event.agent_id_status
  - event.category
  - event.created
  - event.dataset
  - event.kind
  - event.module
  - event.original
  - event.outcome
  - event.reason
  - event.type
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
  - related.hosts
  - related.ip
  - related.user
  - source.address
  - source.as.number
  - source.as.organization.name
  - source.geo.city_name
  - source.geo.continent_name
  - source.geo.country_iso_code
  - source.geo.country_name
  - source.geo.location
  - source.geo.region_iso_code
  - source.geo.region_name
  - source.ip
  - source.port
  - source.user.email
  - source.user.group.name
  - source.user.id
  - source.user.name
  - tags
  - user.email
  - user.id
  - user.name
  - user_agent.name
  - user_agent.os.name
  - user_agent.os.version
  - user_agent.version
  fields:
  - name: cisco_duo
    type:
      type: struct
      fields:
      - name: auth
        type:
          type: struct
          fields:
          - name: access_device
            type:
              type: struct
              fields:
              - name: flash_version
                type: string
              - name: hostname
                type: string
              - name: ip
                type: string
              - name: is_encryption_enabled
                type: string
              - name: is_firewall_enabled
                type: string
              - name: is_password_set
                type: string
              - name: java_version
                type: string
              - name: location
                type:
                  type: struct
                  fields:
                  - name: city
                    type: string
                  - name: country
                    type: string
                  - name: state
                    type: string
              - name: port
                type: long
              - name: security_agents
                type: string
          - name: alias
            type: string
          - name: application
            type:
              type: struct
              fields:
              - name: key
                type: string
              - name: name
                type: string
          - name: auth_device
            type:
              type: struct
              fields:
              - name: as
                type:
                  type: struct
                  fields:
                  - name: number
                    type: long
                  - name: organization
                    type:
                      type: struct
                      fields:
                      - name: name
                        type: string
              - name: geo
                type:
                  type: struct
                  fields:
                  - name: city_name
                    type: string
                  - name: continent_name
                    type: string
                  - name: country_iso_code
                    type: string
                  - name: country_name
                    type: string
                  - name: location
                    type:
                      type: struct
                      fields:
                      - name: lat
                        type: float
                      - name: lon
                        type: float
                  - name: region_iso_code
                    type: string
                  - name: region_name
                    type: string
              - name: ip
                type: string
              - name: location
                type:
                  type: struct
                  fields:
                  - name: city
                    type: string
                  - name: country
                    type: string
                  - name: state
                    type: string
              - name: name
                type: string
              - name: port
                type: long
          - name: email
            type: string
          - name: event_type
            type: string
          - name: factor
            type: string
          - name: ood_software
            type: string
          - name: reason
            type: string
          - name: result
            type: string
          - name: trusted_endpoint_status
            type: string
          - name: txid
            type: string
transform: |2-


  .ecs.version = "8.5.0"

  .event.original = del(.message)

             
  unhandled = true                       
  ## op: json                            
  # {
  #   "field": "event.original",
  #   "target_field": "json",
  #   "ignore_failure": true
  # }                   
  # script                                
  #                        

  if .json.response instanceof List && .json.response.length == 0 { 
      abort
  }

      
             
  unhandled = true                       
  ## op: fingerprint                            
  # {
  #   "fields": [
  #     "json.timestamp",
  #     "json.txid"
  #   ],
  #   "target_field": "_id",
  #   "ignore_missing": true
  # }                   
  # script                                
  #                        

  if .json.timestamp != null { 
      if .json.timestamp != null {                                               
  	  .ts = to_timestamp!(.json.timestamp, "seconds") 
  	}
  }

      
  .event.category = "['authentication']"

  .event.kind = "event"

  .event.outcome = "failure"

  if .json.result == "success" { 
      .event.outcome = "success"
  }

      
  .event.type = "['info']"

  .event.reason = .json.reason

  .source.address = .json.access_device.ip

                                                                  
  _grokked, err = parse_groks(.json.access_device.ip, ["^%{IPV4:json.access_device.ip}:%{PORT:json.access_device.port}$", "^\\[%{IPV6:json.access_device.ip}\\]:%{PORT:json.access_device.port}$", "^%{IPV6NOCOMPRESS:json.access_device.ip}:%{PORT:json.access_device.port}$", "^%{IPV6:json.access_device.ip}%{IPV6PORTSEP}%{PORT:json.access_device.port}$"])  
  if err == null {                                                            
      . |= _grokked                                                            
  }                                                                           

  if .json.access_device.ip != null {                       
      .json.access_device.ip = to_string!(.json.access_device.ip) 
  }                                                  

  if .json.access_device.port != null {                       
      .json.access_device.port = to_int!(.json.access_device.port) 
  }                                                  

  .source.ip = .json.access_device.ip

  .source.port = .json.access_device.port

                                                                  
  _grokked, err = parse_groks(.json.auth_device.ip, ["^%{IPV4:json.auth_device.ip}:%{PORT:json.auth_device.port}$", "^\\[%{IPV6:json.auth_device.ip}\\]:%{PORT:json.auth_device.port}$", "^%{IPV6NOCOMPRESS:json.auth_device.ip}:%{PORT:json.auth_device.port}$", "^%{IPV6:json.auth_device.ip}%{IPV6PORTSEP}%{PORT:json.auth_device.port}$"])  
  if err == null {                                                            
      . |= _grokked                                                            
  }                                                                           

  if .json.auth_device.ip != null {                       
      .json.auth_device.ip = to_string!(.json.auth_device.ip) 
  }                                                  

  if .json.auth_device.port != null {                       
      .json.auth_device.port = to_int!(.json.auth_device.port) 
  }                                                  

  .source.address = .json.access_device.hostname

  .source.user.email = .json.email

  .source.user.id = .json.user.key

  .source.user.name = .json.user.name

  .source.user.group.name = del(.json.user.groups)

  .source.as.number = del(.source.as.asn)

  .source.as.organization.name = del(.source.as.organization_name)

  .cisco_duo.auth.auth_device.as.number = del(.cisco_duo.auth.auth_device.as.asn)

  .cisco_duo.auth.auth_device.as.organization.name = del(.cisco_duo.auth.auth_device.as.organization_name)

  .user.email = .json.email

  .user.name = .json.user.name

  .user.id = .json.user.key

  .user_agent.name = .json.access_device.browser

  .user_agent.version = .json.access_device.browser_version

  .user_agent.os.name = .json.access_device.os

  .user_agent.os.version = .json.access_device.os_version

  .cisco_duo.auth.email = del(.json.email)

  .cisco_duo.auth.event_type = del(.json.event_type)

  .cisco_duo.auth.factor = del(.json.factor)

  .cisco_duo.auth.ood_software = del(.json.ood_software)

  .cisco_duo.auth.reason = del(.json.reason)

  .cisco_duo.auth.result = del(.json.result)

  .cisco_duo.auth.txid = del(.json.txid)

  .cisco_duo.auth.alias = del(.json.alias)

  .cisco_duo.auth.access_device.flash_version = del(.json.access_device.flash_version)

  if .json.access_device.hostname != null { 
      .cisco_duo.auth.access_device.hostname = del(.json.access_device.hostname)
  }

      
  .cisco_duo.auth.access_device.ip = del(.json.access_device.ip)

  .cisco_duo.auth.access_device.port = del(.json.access_device.port)

  .cisco_duo.auth.access_device.is_encryption_enabled = del(.json.access_device.is_encryption_enabled)

  if .cisco_duo.auth.access_device.is_encryption_enabled != null {                       
      .cisco_duo.auth.access_device.is_encryption_enabled = to_string!(.cisco_duo.auth.access_device.is_encryption_enabled) 
  }                                                  

  .cisco_duo.auth.access_device.is_firewall_enabled = del(.json.access_device.is_firewall_enabled)

  if .cisco_duo.auth.access_device.is_firewall_enabled != null {                       
      .cisco_duo.auth.access_device.is_firewall_enabled = to_string!(.cisco_duo.auth.access_device.is_firewall_enabled) 
  }                                                  

  .cisco_duo.auth.access_device.is_password_set = del(.json.access_device.is_password_set)

  if .cisco_duo.auth.access_device.is_password_set != null {                       
      .cisco_duo.auth.access_device.is_password_set = to_string!(.cisco_duo.auth.access_device.is_password_set) 
  }                                                  

  .cisco_duo.auth.access_device.java_version = del(.json.access_device.java_version)

  .cisco_duo.auth.access_device.location.city = del(.json.access_device.location.city)

  .cisco_duo.auth.access_device.location.country = del(.json.access_device.location.country)

  .cisco_duo.auth.access_device.location.state = del(.json.access_device.location.state)

  if .json.access_device.security_agents != null && (
        !(.json.access_device.security_agents instanceof List) ||
        .json.access_device.security_agents.length == 0 ||
        !(.json.access_device.security_agents[0] instanceof Object)
      ) { 
      del(.json.access_device.security_agents)
  }

      
  .cisco_duo.auth.access_device.security_agents = del(.json.access_device.security_agents)

  .cisco_duo.auth.application.key = del(.json.application.key)

  .cisco_duo.auth.application.name = del(.json.application.name)

  .cisco_duo.auth.auth_device.ip = del(.json.auth_device.ip)

  .cisco_duo.auth.auth_device.port = del(.json.auth_device.port)

  .cisco_duo.auth.auth_device.location.city = del(.json.auth_device.location.city)

  .cisco_duo.auth.auth_device.location.country = del(.json.auth_device.location.country)

  .cisco_duo.auth.auth_device.location.state = del(.json.auth_device.location.state)

  .cisco_duo.auth.auth_device.name = del(.json.auth_device.name)

  .cisco_duo.auth.trusted_endpoint_status = del(.json.trusted_endpoint_status)

  if .source.ip != null { 
      .related.ip = push!(.related.ip, .{source.ip}) 
  }

      
  if .cisco_duo.auth.auth_device.ip != null { 
      .related.ip = push!(.related.ip, .{cisco_duo.auth.auth_device.ip}) 
  }

      
  if .source.user.name != null { 
      .related.user = push!(.related.user, .{source.user.name}) 
  }

      
  if .source.address != null { 
      .related.hosts = push!(.related.hosts, .{source.address}) 
  }

      
  if .cisco_duo.auth.access_device.hostname != null { 
      .related.hosts = push!(.related.hosts, .{cisco_duo.auth.access_device.hostname}) 
  }

      
  del(.json)
name: duo_auth
