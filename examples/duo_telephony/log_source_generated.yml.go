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
  - event.kind
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
      - name: telephony
        type:
          type: struct
          fields:
          - name: credits
            type: int
          - name: event_type
            type: string
          - name: phone_number
            type: string
          - name: type
            type: string
transform: |2-


  .ecs.version = "8.5.0"

  .event.kind = "event"

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
  #     "json.phone",
  #     "json.context",
  #     "json.type"
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

      
  .cisco_duo.telephony.event_type = del(.json.context)

  .cisco_duo.telephony.credits = del(.json.credits)

  .cisco_duo.telephony.phone_number = del(.json.phone)

  .cisco_duo.telephony.type = del(.json.type)

  del(.json)
name: duo_telephony
