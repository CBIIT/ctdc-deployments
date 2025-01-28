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
            # "NEW_RELIC_APP_NAME":"{}-{}-{}".format(self.namingPrefix, config['main']['tier'], service),
            # "NEW_RELIC_DISTRIBUTED_TRACING_ENABLED":"true",
            # "NEW_RELIC_HOST":"gov-collector.newrelic.com",
            # "NEW_RELIC_LABELS":"Project:{};Environment:{}".format('bento', config['main']['tier']),
            # "NEW_RELIC_NO_CONFIG_FILE":"true",
            "NODE_LEVEL":"Study Arm(s)",
            "NODE_LEVEL_ACCESS":"true",
            "PUBLIC_ACCESS":"Metadata Only",
            "REACT_APP_ABOUT_CONTENT_URL":config[service]['about_content_url'],
            "REACT_APP_AUTH_API":self.app_url,
            "REACT_APP_AUTH_SERVICE_API":"/api/auth/",
            "REACT_APP_BACKEND_API":"/v1/graphql/",
            "REACT_APP_BACKEND_PUBLIC_API":"/v1/public-graphql/",
            "REACT_APP_BE_VERSION":config['backend']['image'],
            "REACT_APP_FE_VERSION":config[service]['image'],
            "REACT_APP_FILE_SERVICE_API":"/api/files/",
            "REACT_APP_GA_TRACKING_ID":"",
            "REACT_APP_USER_SERVICE_API":"/api/users/",
        }

    secrets={
             #"NEW_RELIC_LICENSE_KEY":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "fe_newrelic", secret_name='monitoring/newrelic'), 'api_key'),
             "REACT_APP_NIH_CLIENT_ID":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "fe_provider_id", secret_name='auth/provider/nih'), 'nih_client_id'),
             "REACT_APP_NIH_AUTH_URL":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "fe_provider_url", secret_name='auth/provider/nih'), 'nih_client_url'),
             "REACT_APP_GOOGLE_CLIENT_ID":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "fe_google", secret_name='auth/provider/google'), 'idp_client_id'),
         }
    
    taskDefinition = ecs.FargateTaskDefinition(self,
        "{}-{}-taskDef".format(self.namingPrefix, service),
        cpu=config.getint(service, 'cpu'),
        memory_limit_mib=config.getint(service, 'memory')
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
    
    taskDefinition.add_container(
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
