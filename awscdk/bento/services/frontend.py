from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_ecr as ecr
from aws_cdk import aws_secretsmanager as secretsmanager

class frontendService:
  def createService(self, config):

    ### Frontend Service ###############################################################################################################
    service = "frontend"

    # Set container configs
    if config.has_option(service, 'command'):
        command = [config[service]['command']]
    else:
        command = None
    
    environment={
            "NEW_RELIC_APP_NAME":"crdc-dev-ctdc-frontend",
            "NEW_RELIC_DISTRIBUTED_TRACING_ENABLED":"true",
            "NEW_RELIC_LABELS":"Project:{};Environment:{}".format('ctdc', config['main']['tier']),
            "NRIA_IS_FORWARD_ONLY":"true",
            "NRIA_OVERRIDE_HOST_ROOT":"",
            "NRIA_PASSTHROUGH_ENVIRONMENT":"ECS_CONTAINER_METADATA_URI,ECS_CONTAINER_METADATA_URI_V4,FARGATE",
            "NRIA_CUSTOM_ATTRIBUTES":"{\"nrDeployMethod\":\"downloadPage\"}",
            # "NEW_RELIC_HOST":"gov-collector.newrelic.com",
            # "NEW_RELIC_NO_CONFIG_FILE":"true",
            "NEW_RELIC_HOST":"gov-collector.newrelic.com",
            "NODE_LEVEL":"Study Arm(s)",
            "NODE_LEVEL_ACCESS":"gov-collector.newrelic.com",
            "PUBLIC_ACCESS":"Metadata Only",
            "REACT_APP_ABOUT_CONTENT_URL":config[service]['about_content_url'],
            "REACT_APP_AUTH_API":self.app_url,
            "REACT_APP_AUTH":"true",
            "REACT_APP_AUTH_SERVICE_API":"https://{}-{}.{}/api/auth/".format(config['main']['subdomain'], config['main']['tier'], config['main']['domain']),
            "REACT_APP_BACKEND_API":"https://{}-{}.{}/v1/graphql/".format(config['main']['subdomain'], config['main']['tier'], config['main']['domain']),
            "REACT_APP_BACKEND_PUBLIC_API":"/v1/public-graphql/",
            "REACT_APP_BE_VERSION":config['backend']['image'],
            "REACT_APP_FE_VERSION":config[service]['image'],
            "REACT_APP_FILE_SERVICE_API":"https://{}-{}.{}/api/files/".format(config['main']['subdomain'], config['main']['tier'], config['main']['domain']),
            "REACT_APP_INTEROP_SERVICE_URL":"https://{}-{}.{}/api/interoperation/graphql".format(config['main']['subdomain'], config['main']['tier'], config['main']['domain']),
            "REACT_APP_BACKEND_GETUSERINFO_API":"https://k9dc.essential-dev.com/fence/login/",
            "REACT_APP_LOGIN_URL":"https://nci-crdc-staging.datacommons.io/user/oauth2/authorize?client_id=$DCF_CLIENT_ID&response_type=code&redirect_uri=https://{}.login&scope=openid%20user%20data".format(config['main']['domain']),
            #"REACT_APP_USER_SERVICE_API":"/api/users/",
        }

    secrets={
            "NEW_RELIC_LICENSE_KEY":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "fe_newrelic", secret_name='monitoring/newrelic'), 'api_key'),
            #  "REACT_APP_NIH_CLIENT_ID":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "fe_provider_id", secret_name='auth/provider/nih'), 'nih_client_id'),
            #  "REACT_APP_NIH_AUTH_URL":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "fe_provider_url", secret_name='auth/provider/nih'), 'nih_client_url'),
            #  "REACT_APP_GOOGLE_CLIENT_ID":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "fe_google", secret_name='auth/provider/google'), 'idp_client_id'),
            #"REACT_APP_GA_TRACKING_ID":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "fe_google", secret_name='bento/ctdc/dev'), 'google_id'),
            "REACT_APP_GA_TRACKING_ID":ecs.Secret.from_secrets_manager(self.secret, 'google_id'),
        
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
    
    # Frontend Container
    frontend_container = taskDefinition.add_container(
        service,
        #image=ecs.ContainerImage.from_registry("{}:{}".format(fe_repo.repository_uri, config[service]['image'])),
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

    # Sumo Logic Container
    # sumo_logic_container = taskDefinition.add_container(
    #     "sumologic-firelens",
    #     image=ecs.ContainerImage.from_registry("public.ecr.aws/aws-observability/aws-for-fluent-bit:stable"),
    #     cpu=0,
    #     essential=True,
    #     firelens_config=ecs.FirelensConfig(type=ecs.FirelensLogRouterType.FLUENTBIT, options={"enable-ecs-log-metadata": "true"})
    # )
    
    # New Relic Container
    new_relic_container = taskDefinition.add_container(
        "newrelic-infra",
        image=ecs.ContainerImage.from_registry("newrelic/nri-ecs:1.9.2"),
        cpu=0,
        essential=True,
        secrets={"NRIA_LICENSE_KEY":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "fenr_newrelic", secret_name='monitoring/newrelic'), 'api_key'),},
        environment={
            "NEW_RELIC_HOST":"gov-collector.newrelic.com",
            "NEW_RELIC_APP_NAME":"{}-{}-backend".format(config['main']['project'], config['main']['tier']),
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

    ecsTarget = self.listener.add_targets("ECS-{}-Target".format(service),
        port=int(config[service]['port']),
        protocol=elbv2.ApplicationProtocol.HTTP,
        health_check = elbv2.HealthCheck(
            path=config[service]['health_check_path']),
        targets=[ecsService],)

    elbv2.ApplicationListenerRule(self, id="alb-{}-rule".format(service),
        conditions=[
            elbv2.ListenerCondition.path_patterns(config[service]['path'].split(','))
        ],
        priority=int(config[service]['priority_rule_number']),
        listener=self.listener,
        target_groups=[ecsTarget])
