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
  - related.hosts
  - related.user
  - tags
  - user.name
  fields:
  - name: cisco_duo
    type:
      type: struct
      fields:
      - name: offline_enrollment
        type:
          type: struct
          fields:
          - name: action
            type: string
          - name: description
            type:
              type: struct
              fields:
              - name: factor
                type: string
              - name: hostname
                type: string
              - name: user_agent
                type: string
          - name: object
            type: string
          - name: user
            type:
              type: struct
              fields:
              - name: name
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
  #     "json.action",
  #     "json.description",
  #     "json.object",
  #     "json.username"
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

      
             
  unhandled = true                       
  ## op: json                            
  # {
  #   "field": "json.description",
  #   "target_field": "json_description",
  #   "ignore_failure": true
  # }                   
  # script                                
  #                        

  .user.name = .json.username

  .cisco_duo.offline_enrollment.action = del(.json.action)

  .cisco_duo.offline_enrollment.description.hostname = del(.json_description.hostname)

  .cisco_duo.offline_enrollment.description.user_agent = del(.json_description.user_agent)

  .cisco_duo.offline_enrollment.description.factor = del(.json_description.factor)

  .cisco_duo.offline_enrollment.object = del(.json.object)

  .cisco_duo.offline_enrollment.user.name = del(.json.username)

  if .cisco_duo.offline_enrollment.description.hostname != null { 
      .related.hosts = push(.related.hosts, .{cisco_duo.offline_enrollment.description.hostname}) 
  }

      
  if .user.name != null { 
      .related.user = push(.related.user, .{user.name}) 
  }

      
  del(.json)

  if .json_description != null { 
      del(.json_description)
  }

      
name: duo_offline_enrollment
