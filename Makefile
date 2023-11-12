.DEFAULT_GOAL := aws_cloudtrail_default

AWS_CLOUDTRAIL := aws_cloudtrail_default

check_defined = \
    $(strip $(foreach 1,$1, \
        $(call __check_defined,$1,$(strip $(value 2)))))

__check_defined = \
    $(if $(value $1),, \
        $(error Undefined $1$(if $2, ($2))))

define generate_ecs_data_stream_dir
    $(ECS_INTEGRATIONS_DIR)/packages/$(1)/data_stream/$(2)
endef

define validate_environment
    $(call check_defined,ECS_INTEGRATIONS_DIR,ECS_INTEGRATIONS_DIR environment variable)
    $(call check_defined,MATANO_INTEGRATIONS_DIR,MATANO_INTEGRATIONS_DIR environment variable)
endef

export ECS_INTEGRATIONS_DIR
export MATANO_INTEGRATIONS_DIR

aws_cloudtrail_default:
	$(eval ECS_DATA_STREAM_DIR := $(call generate_ecs_data_stream_dir,aws,cloudtrail))
	$(call validate_environment)

	python3 main2.py \
	    --matano-integrations-dir $(MATANO_INTEGRATIONS_DIR) \
	    --log-source aws_cloudtrail \
	    --table-name default \
	    --ecs-data-stream-dir $(ECS_DATA_STREAM_DIR) \
	    --pin-to-log-source \
	    --exclude-test-sync-pattern 'insight|digest' \
		$(or $(EXTRA_FLAGS),$(filter-out $@,$(MAKECMDGOALS)))

aws_cloudtrail_digest:
	$(eval ECS_DATA_STREAM_DIR := $(call generate_ecs_data_stream_dir,aws,cloudtrail))
	$(call validate_environment)

	python3 main2.py \
	    --matano-integrations-dir $(MATANO_INTEGRATIONS_DIR) \
	    --log-source aws_cloudtrail \
	    --table-name digest \
	    --ecs-data-stream-dir $(ECS_DATA_STREAM_DIR) \
	    --pin-to-log-source \
	    --include-test-sync-pattern 'digest' \
		$(or $(EXTRA_FLAGS),$(filter-out $@,$(MAKECMDGOALS)))

aws_cloudtrail_insights:
	$(eval ECS_DATA_STREAM_DIR := $(call generate_ecs_data_stream_dir,aws,cloudtrail))
	$(call validate_environment)

	python3 main2.py \
	    --matano-integrations-dir $(MATANO_INTEGRATIONS_DIR) \
	    --log-source aws_cloudtrail \
	    --table-name insights \
	    --ecs-data-stream-dir $(ECS_DATA_STREAM_DIR) \
	    --pin-to-log-source \
	    --include-test-sync-pattern 'insight' \
		$(or $(EXTRA_FLAGS),$(filter-out $@,$(MAKECMDGOALS)))

aws_cloudtrail: EXTRA_FLAGS=$(filter-out $@,$(MAKECMDGOALS))
aws_cloudtrail: aws_cloudtrail_default aws_cloudtrail_digest aws_cloudtrail_insights

okta_system:
	$(eval ECS_DATA_STREAM_DIR := $(call generate_ecs_data_stream_dir,okta,system))
	$(call validate_environment)

	python3 main2.py \
	    --matano-integrations-dir $(MATANO_INTEGRATIONS_DIR) \
	    --log-source okta \
	    --table-name system \
	    --ecs-data-stream-dir $(ECS_DATA_STREAM_DIR) \
		$(or $(EXTRA_FLAGS),$(filter-out $@,$(MAKECMDGOALS)))

