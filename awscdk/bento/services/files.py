from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_ecr as ecr
from aws_cdk import aws_secretsmanager as secretsmanager

class filesService:
  def createService(self, config):

    ### Files Service ###############################################################################################################
    service = "files"

    # Set container configs
    if config.has_option(service, 'command'):
        command = [config[service]['command']]
    else:
        command = None

    environment={
            "NEW_RELIC_APP_NAME":"crdc-dev-ctdc-files",
            "NEW_RELIC_HOST":"gov-collector.newrelic.com",
            "NEW_RELIC_DISTRIBUTED_TRACING_ENABLED":"true",
            "NEW_RELIC_LABELS":"Project:{};Environment:{}".format('ctdc', config['main']['tier']),
            "NRIA_PASSTHROUGH_ENVIRONMENT":"ECS_CONTAINER_METADATA_URI,ECS_CONTAINER_METADATA_URI_V4,FARGATE",
            "AUTH_ENABLED":"false",
            "NRIA_IS_FORWARD_ONLY":"true",
            "NRIA_CUSTOM_ATTRIBUTES":"{\"nrDeployMethod\":\"downloadPage\"}",
            "NRIA_OVERRIDE_HOST_ROOT":"",
            "AUTH_URL":"/api/auth/authenticated",
            "AUTHORIZATION_ENABLED":"true",
            "BACKEND_URL":"/v1/graphql/",
            "DATE":"2024-07-09",
            # "MYSQL_PORT":"3306",
            # "MYSQL_SESSION_ENABLED":"true",
            #"NEO4J_URI":"bolt://{}:7687".format(config['db']['neo4j_ip']),
            "PROJECT":"CTDC",
            "URL_SRC":"CLOUD_FRONT",
            "VERSION":config[service]['image'],
        }

    secrets={
            "NEW_RELIC_LICENSE_KEY":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "files_newrelic", secret_name='monitoring/newrelic'), 'api_key'),
            #"NEO4J_PASSWORD":ecs.Secret.from_secrets_manager(self.secret, 'neo4j_password'),
            #"NEO4J_USER":ecs.Secret.from_secrets_manager(self.secret, 'neo4j_user'),
            #"CF_PRIVATE_KEY":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "files_cf_key", secret_name="ec2-ssh-key/{}/private".format(self.cfKeys.key_pair_name)), ''),
            #"CF_KEY_PAIR_ID":ecs.Secret.from_secrets_manager(self.secret, 'cf_key_pair_id'),
            #"CF_URL":ecs.Secret.from_secrets_manager(self.secret, 'cf_url'),
            #"TOKEN_SECRET":ecs.Secret.from_secrets_manager(self.secret, 'token_secret'),
            "COOKIE_SECRET":ecs.Secret.from_secrets_manager(self.secret, 'cookie_secret'),
            "DCF_FILE_URL":ecs.Secret.from_secrets_manager(self.secret, 'dcf_file_url'),

            # "MYSQL_DATABASE":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'dbname'),
            # "MYSQL_HOST":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'host'),
            # "MYSQL_PASSWORD":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'password'),
            # "MYSQL_USER":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'username'),

            # "MYSQL_DATABASE": ecs.Secret.from_secrets_manager(self.auroraInstance.secret, 'dbname'),
            # "MYSQL_HOST": ecs.Secret.from_secrets_manager(self.auroraInstance.secret, 'host'),
            # "MYSQL_PASSWORD": ecs.Secret.from_secrets_manager(self.auroraInstance.secret, 'password'),
            # "MYSQL_USER": ecs.Secret.from_secrets_manager(self.auroraInstance.secret, 'username'),
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
            path=config[service]['health_check_path']),
        targets=[ecsService],)

    elbv2.ApplicationListenerRule(self, id="alb-{}-rule".format(service),
        conditions=[
            elbv2.ListenerCondition.path_patterns(config[service]['path'].split(','))
        ],
        priority=int(config[service]['priority_rule_number']),
        listener=self.listener,
        target_groups=[ecsTarget])
