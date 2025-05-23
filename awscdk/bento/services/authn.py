from aws_cdk import Duration
from aws_cdk import aws_iam as iam
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_ecr as ecr
from aws_cdk import aws_secretsmanager as secretsmanager

class authnService:
  def createService(self, config):

    ### AuthN Service ###############################################################################################################
    service = "authn"

    # Set container configs
    if config.has_option(service, 'command'):
        command = [config[service]['command']]
    else:
        command = None

    environment={
            "NEW_RELIC_APP_NAME":"{}-{}-backend".format(config['main']['project'], config['main']['tier']),
            "NEW_RELIC_LABELS":"Project:{};Environment:{}".format('ctdc', config['main']['tier']),
            "DATE":"2024-05-21",
            "MYSQL_PORT":"3306",
            "MYSQL_SESSION_ENABLED":"true",
            "MYSQL_DATABASE":"ctdc",
            "DATABASE_TYPE":"mysql",
            "NEO4J_URI":"bolt://{}:7687".format(config['db']['neo4j_ip']),
            "IDP":"nih",
            "VERSION":config[service]['image'],
        }

    secrets={
            "NEW_RELIC_LICENSE_KEY":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "auth_newrelic", secret_name='monitoring/newrelic'), 'api_key'),
            "COOKIE_SECRET":ecs.Secret.from_secrets_manager(self.secret, 'cookie_secret'),\
            
            "DCF_CLIENT_ID":ecs.Secret.from_secrets_manager(self.secret, 'dcf_client_id'),
            "DCF_CLIENT_SECRET":ecs.Secret.from_secrets_manager(self.secret, 'dcf_client_secret'),
            "DCF_BASE_URL":ecs.Secret.from_secrets_manager(self.secret, 'dcf_base_url'),
            "DCF_REDIRECT_URL":ecs.Secret.from_secrets_manager(self.secret, 'dcf_redirect_url'),
            "DCF_USERINFO_URL":ecs.Secret.from_secrets_manager(self.secret, 'dcf_userinfo_url'),
            "DCF_AUTHORIZE_URL":ecs.Secret.from_secrets_manager(self.secret, 'dcf_authorize_url'),
            "DCF_TOKEN_URL":ecs.Secret.from_secrets_manager(self.secret, 'dcf_token_url'),
            "DCF_LOGOUT_UR":ecs.Secret.from_secrets_manager(self.secret, 'dcf_logout_url'),
            "DCF_SCOPE":ecs.Secret.from_secrets_manager(self.secret, 'dcf_scope'),
            "DCF_PROMPT":ecs.Secret.from_secrets_manager(self.secret, 'dcf_prompt'),
            "MYSQL_HOST":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'host'),
            "MYSQL_PASSWORD":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'password'),
            "MYSQL_USER":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'username'),
        }
    
    taskDefinition = ecs.FargateTaskDefinition(self,
        "{}-{}-taskDef".format(self.namingPrefix, service),
        cpu=config.getint(service, 'taskcpu'),
        memory_limit_mib=config.getint(service, 'taskmemory')
    )

    # Grant ECR access
    taskDefinition.add_to_execution_role_policy(
            iam.PolicyStatement(
                actions=[
                    "ecr:UploadLayerPart",
                    "ecr:PutImage",
                    "ecr:ListTagsForResource",
                    "ecr:InitiateLayerUpload",
                    "ecr:GetRepositoryPolicy",
                    "ecr:GetLifecyclePolicy",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:DescribeRepositories",
                    "ecr:CompleteLayerUpload",
                    "ecr:BatchGetImage",
                    "ecr:BatchCheckLayerAvailability"
                ],
                effect=iam.Effect.ALLOW,
                resources=["arn:aws:ecr:us-east-1:986019062625:repository/*"]
            )
        )

    taskDefinition.add_to_execution_role_policy(
            iam.PolicyStatement(
                actions=["ecr:GetAuthorizationToken"],
                effect=iam.Effect.ALLOW,
                resources=["*"]
            )
        )
    
    ecr_repo = ecr.Repository.from_repository_arn(self, "{}_repo".format(service), repository_arn=config[service]['repo'])
    
    # Auth Container
    auth_container = taskDefinition.add_container(
        service,
        #image=ecs.ContainerImage.from_registry("{}:{}".format(config[service]['repo'], config[service]['image'])),
        image=ecs.ContainerImage.from_ecr_repository(repository=ecr_repo, tag=config[service]['image']),
        cpu=config.getint(service, 'cpu'),
        memory_limit_mib=config.getint(service, 'memory'),
        port_mappings=[ecs.PortMapping(container_port=config.getint(service, 'port'), name=service)],
        command=command,
        environment=environment,
        secrets=secrets,
        logging=ecs.LogDrivers.aws_logs(
            stream_prefix="{}-{}".format(self.namingPrefix, service)
        )
    )

    # # For Sumo Logs use
    
    # auth_container = taskDefinition.add_container(
    #     service,
    #     image=ecs.ContainerImage.from_ecr_repository(repository=ecr_repo, tag=config[service]['image']),
    #     cpu=config.getint(service, 'cpu'),
    #     memory_limit_mib=config.getint(service, 'memory'),
    #     port_mappings=[ecs.PortMapping(container_port=config.getint(service, 'port'), name=service)],
    #     command=command,
    #     environment=environment,
    #     secrets=secrets,
    #     logging=ecs.LogDrivers.firelens(
    #         options={
    #             "Name": "http",
    #             "Host": config['sumologic']['collector_endpoint'],
    #             "URI": "/receiver/v1/http/{}".format(config['sumologic']['collector_token']),
    #             "Port": "443",
    #             "tls": "on",
    #             "tls.verify": "off",
    #             "Retry_Limit": "2",
    #             "Format": "json_lines"
    #         }
    #     )
    # )


    # # Sumo Logic FireLens Log Router Container
    # sumo_logic_container = taskDefinition.add_firelens_log_router(
    #     "sumologic-firelens",
    #     image=ecs.ContainerImage.from_registry("public.ecr.aws/aws-observability/aws-for-fluent-bit:stable"),
    #     firelens_config=ecs.FirelensConfig(
    #         type=ecs.FirelensLogRouterType.FLUENTBIT,
    #         options=ecs.FirelensOptions(
    #             enable_ecs_log_metadata=True
    #         )
    #     ),
    # essential=True
    # )


    # New Relic Container
    new_relic_container = taskDefinition.add_container(
        "newrelic-infra",
        image=ecs.ContainerImage.from_registry("newrelic/nri-ecs:1.9.2"),
        cpu=0,
        essential=True,
        secrets={"NRIA_LICENSE_KEY":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "authnr_newrelic", secret_name='monitoring/newrelic'), 'api_key'),},
        environment={
            "NEW_RELIC_HOST":"gov-collector.newrelic.com",
            "NEW_RELIC_APP_NAME":"{}-{}-files".format(config['main']['project'], config['main']['tier']),
            "NRIA_IS_FORWARD_ONLY":"true",
            "NEW_RELIC_DISTRIBUTED_TRACING_ENABLED":"true",
            "NRIA_PASSTHROUGH_ENVIRONMENT":"ECS_CONTAINER_METADATA_URI,ECS_CONTAINER_METADATA_URI_V4,FARGATE",
            "FARGATE":"true",
            "NRIA_CUSTOM_ATTRIBUTES": '{"nrDeployMethod":"downloadPage"}',
            "NRIA_OVERRIDE_HOST_ROOT": ""
            },
    )

    ecsService = ecs.FargateService(self,
        "{}-{}-service".format(self.namingPrefix, service),
        cluster=self.ECSCluster,
        task_definition=taskDefinition,
        enable_execute_command=True,
        min_healthy_percent=50,
        max_healthy_percent=200,
        circuit_breaker=ecs.DeploymentCircuitBreaker(
            enable=True,
            rollback=True
        ),
    )
    #ecsService.connections.allow_to_default_port(self.auroraCluster)

    ecsTarget = self.listener.add_targets("ECS-{}-Target".format(service),
        port=int(config[service]['port']),
        protocol=elbv2.ApplicationProtocol.HTTP,
        health_check = elbv2.HealthCheck(
            path=config[service]['health_check_path'],
            timeout=Duration.seconds(config.getint(service, 'health_check_timeout')),
            interval=Duration.seconds(config.getint(service, 'health_check_interval')),),
        targets=[ecsService],)

    elbv2.ApplicationListenerRule(self, id="alb-{}-rule".format(service),
        conditions=[
            elbv2.ListenerCondition.path_patterns(config[service]['path'].split(','))
        ],
        priority=int(config[service]['priority_rule_number']),
        listener=self.listener,
        target_groups=[ecsTarget])
