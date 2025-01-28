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
            # "NEW_RELIC_APP_NAME":"bento-perf-authN",
            "AUTHORIZATION_ENABLED":"true",
            "AUTHORIZATION_URL":"/api/users/graphql",
            "DATE":"2024-05-21",
            "PROJECT":"bento",
            "EMAIL_SMTP_HOST":"email-smtp.us-east-1.amazonaws.com",
            "EMAIL_SMTP_PORT":"465",
            "EMAILS_ENABLED":"true",
            "GOOGLE_REDIRECT_URL":self.app_url,
            "IDP":"google",
            "MYSQL_PORT":"3306",
            "MYSQL_SESSION_ENABLED":"true",
            "NEO4J_URI":"bolt://{}:7687".format(config['db']['neo4j_ip']),
            "NIH_AUTHORIZE_URL":"https://stsstg.nih.gov/auth/oauth/v2/authorize",
            "NIH_BASE_URL":"https://stsstg.nih.gov",
            "NIH_LOGOUT_URL":"https://stsstg.nih.gov/connect/session/logout",
            "NIH_PROMPT":"login",
            "NIH_REDIRECT_URL":self.app_url,
            "NIH_SCOPE":"openid email profile",
            "NIH_TOKEN_URL":"https://stsstg.nih.gov/auth/oauth/v2/token",
            "NIH_USERINFO_URL":"https://stsstg.nih.gov/openid/connect/v1/userinfo",
            "SESSION_TIMEOUT":"1800",
            "VERSION":config[service]['image'],
        }

    secrets={
            # "NEW_RELIC_LICENSE_KEY":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "be_newrelic", secret_name='monitoring/newrelic'), 'api_key'),
            "NEO4J_PASSWORD":ecs.Secret.from_secrets_manager(self.secret, 'neo4j_password'),
            "NEO4J_USER":ecs.Secret.from_secrets_manager(self.secret, 'neo4j_user'),
            "TOKEN_SECRET":ecs.Secret.from_secrets_manager(self.secret, 'token_secret'),
            "COOKIE_SECRET":ecs.Secret.from_secrets_manager(self.secret, 'cookie_secret'),
            "EMAIL_USER":ecs.Secret.from_secrets_manager(self.secret, 'email_user'),
            "EMAIL_PASSWORD":ecs.Secret.from_secrets_manager(self.secret, 'email_password'),
            "GOOGLE_CLIENT_ID":ecs.Secret.from_secrets_manager(self.secret, 'google_client_id'),
            "GOOGLE_CLIENT_SECRET":ecs.Secret.from_secrets_manager(self.secret, 'google_client_secret'),
            "NIH_CLIENT_ID":ecs.Secret.from_secrets_manager(self.secret, 'nih_client_id'),
            "NIH_CLIENT_SECRET":ecs.Secret.from_secrets_manager(self.secret, 'nih_client_secret'),\
            
            #  "MYSQL_DATABASE":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'dbname'),
            #  "MYSQL_HOST":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'host'),
            #  "MYSQL_PASSWORD":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'password'),
            #  "MYSQL_USER":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'username'),

            "MYSQL_DATABASE": ecs.Secret.from_secrets_manager(self.auroraInstance.secret, 'dbname'),
            "MYSQL_HOST": ecs.Secret.from_secrets_manager(self.auroraInstance.secret, 'host'),
            "MYSQL_PASSWORD": ecs.Secret.from_secrets_manager(self.auroraInstance.secret, 'password'),
            "MYSQL_USER": ecs.Secret.from_secrets_manager(self.auroraInstance.secret, 'username'),
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
