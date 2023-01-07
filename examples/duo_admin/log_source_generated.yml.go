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
  - event.action
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
  - message
  - related.user
  - source.as.number
  - source.as.organization.name
  - tags
  - user.changes.email
  - user.changes.name
  - user.email
  - user.name
  - user.target.name
  fields:
  - name: cisco_duo
    type:
      type: struct
      fields:
      - name: admin
        type:
          type: struct
          fields:
          - name: action
            type: string
          - name: action_performed_on
            type: string
          - name: flattened
            type: string
          - name: user
            type:
              type: struct
              fields:
              - name: name
                type: string
transform: |-
  .event.type = []

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

      
  if .json.action instanceof String && ["admin_2fa_error","admin_account_switch","admin_activation_create","admin_activation_delete","admin_activate_duo_push","admin_create","admin_delete","admin_factor_restrictions_update","admin_login","admin_login_error","admin_reactivates_duo_push","admin_reset_password","admin_self_activate","admin_send_reset_password_email","admin_update","adminapi_request_ip_denied","bypass_create","bypass_delete","bypass_view","phone_associate","phone_create","phone_delete","phone_disassociate","phone_update","group_create","group_delete","group_update","user_bulk_activate","user_bulk_enroll","user_create","user_delete","user_import","user_pending_delete","user_restore","user_update"]contains(, .json.action) { 
      .event.category = "['iam']"
  }

      
  .event.kind = "event"

  .event.outcome = "success"

  if .json.action instanceof String && ["ad_sync_failed","admin_2fa_error","admin_login_error","azure_sync_fail","openldap_sync_failed"]contains(, .json.action) { 
      .event.outcome = "failure"
  }

      
  if .json.action instanceof String && ["activation_create_link","activation_delete_link","activation_send_link","admin_2fa_error","admin_account_switch","admin_activation_create","admin_activation_delete","admin_activate_duo_push","admin_create","admin_delete","admin_factor_restrictions_update","admin_login","admin_login_error","admin_reactivates_duo_push","admin_reset_password","admin_self_activate","admin_send_reset_password_email","admin_update","adminapi_request_ip_denied"]contains(, .json.action) { 
      .event.type = push(.event.type, "admin") 
  }

      
  if .json.action instanceof String && ["group_create","group_delete","group_update","integration_group_policy_add","integration_group_policy_remove","policy_create","policy_delete","policy_update"]contains(, .json.action) { 
      .event.type = push(.event.type, "group") 
  }

      
  if .json.action instanceof String && ["ad_sync_by_user_begin","ad_sync_by_user_finish","azure_sync_by_user_begin","azure_sync_by_user_finish","bypass_create","bypass_delete","bypass_view","openldap_sync_begin","openldap_sync_by_user_begin","phone_associate","phone_create","phone_delete","phone_disassociate","phone_update","user_bulk_activate","user_bulk_enroll","user_create","user_delete","user_import","user_pending_delete","user_restore","user_update"]contains(, .json.action) { 
      .event.type = push(.event.type, "user") 
  }

      
  if .json.action instanceof String && ["ad_sync_begin","ad_sync_failed","ad_sync_finish","azure_directory_create","azure_directory_update","azure_directory_delete","azure_sync_begin","azure_sync_finish","azure_sync_fail","create_child_customer","credits_update","customer_update","delete_child_customer","directory_create","directory_delete","directory_groups_update","directory_sync_pause","directory_sync_resume","directory_update","edition_update","feature_add","feature_delete","hardtoken_create","hardtoken_delete","hardtoken_resync","hardtoken_update","integration_create","integration_delete","integration_policy_assign","integration_policy_unassign","integration_skey_view","integration_update","openldap_sync_by_user_finish","openldap_sync_config_download","openldap_sync_failed","openldap_sync_finish","regen_mobile","regen_sms","resend_enroll_codes","send_enroll_code"]contains(, .json.action) { 
      .event.type = push(.event.type, "info") 
  }

      
  if .json.action instanceof String && contains(.json.action, "create") { 
      .event.type = push(.event.type, "creation") 
  }

      
  if .json.action instanceof String && contains(.json.action, "update") { 
      .event.type = push(.event.type, "change") 
  }

      
  if .json.action instanceof String && contains(.json.action, "delete") { 
      .event.type = push(.event.type, "deletion") 
  }

      
  .message = .json.description

  if .json.description != null { 
                 
  	unhandled = true                       
  	## op: json                            
  	# {
  	#   "field": "json.description",
  	#   "target_field": "cisco_duo.admin.flattened",
  	#   "ignore_failure": true
  	# }                   
  	# script                                
  	#                        
  }

      
  .event.reason = .{message}

  .event.action = .json.action

  .user.name = .json.username

  if .event.action == "admin_self_activate" { 
      .user.email = .cisco_duo.admin.flattened.email
  }

      
  if .event.action == "user_update" { 
      .user.changes.name = .cisco_duo.admin.flattened.realname
  }

      
  if .event.action == "user_update" { 
      .user.changes.email = .cisco_duo.admin.flattened.email
  }

      
  .user.target.name = .json.object

  .cisco_duo.admin.action = del(.json.action)

  .cisco_duo.admin.user.name = del(.json.username)

  if .json.object != null { 
      .cisco_duo.admin.action_performed_on = del(.json.object)
  }

      
  if .cisco_duo.admin.flattened != null { 
      del(.message)
  	del(.event.reason)
  }

      
  if .user.name != null { 
      .related.user = push(.related.user, .{user.name}) 
  }

      
  del(.json)
name: duo_admin
