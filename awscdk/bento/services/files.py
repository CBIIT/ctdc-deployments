from aws_cdk import aws_elasticloadbalancingv2 as elbv2
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
            # "NEW_RELIC_APP_NAME":"bento-cdk-files",
            "AUTH_ENABLED":"false",
            "AUTH_URL":"/api/auth/authenticated",
            "AUTHORIZATION_ENABLED":"true",
            "BACKEND_URL":"/v1/graphql/",
            "DATE":"2024-07-09",
            "MYSQL_PORT":"3306",
            "MYSQL_SESSION_ENABLED":"true",
            #"NEO4J_URI":"bolt://{}:7687".format(config['db']['neo4j_ip']),
            "PROJECT":"BENTO",
            "URL_SRC":"CLOUD_FRONT",
            "VERSION":config[service]['image'],
        }

    secrets={
            # "NEW_RELIC_LICENSE_KEY":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "files_newrelic", secret_name='monitoring/newrelic'), 'api_key'),
            #"NEO4J_PASSWORD":ecs.Secret.from_secrets_manager(self.secret, 'neo4j_password'),
            #"NEO4J_USER":ecs.Secret.from_secrets_manager(self.secret, 'neo4j_user'),
            "CF_PRIVATE_KEY":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "files_cf_key", secret_name="ec2-ssh-key/{}/private".format(self.cfKeys.key_pair_name)), ''),
            "CF_KEY_PAIR_ID":ecs.Secret.from_secrets_manager(self.secret, 'cf_key_pair_id'),
            "CF_URL":ecs.Secret.from_secrets_manager(self.secret, 'cf_url'),
            "TOKEN_SECRET":ecs.Secret.from_secrets_manager(self.secret, 'token_secret'),
            "COOKIE_SECRET":ecs.Secret.from_secrets_manager(self.secret, 'cookie_secret'),

            "MYSQL_DATABASE":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'dbname'),
            "MYSQL_HOST":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'host'),
            "MYSQL_PASSWORD":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'password'),
            "MYSQL_USER":ecs.Secret.from_secrets_manager(self.auroraCluster.secret, 'username'),
        }
    
    taskDefinition = ecs.FargateTaskDefinition(self,
        "{}-{}-taskDef".format(self.namingPrefix, service),
        cpu=config.getint(service, 'cpu'),
        memory_limit_mib=config.getint(service, 'memory')
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
    ecsService.connections.allow_to_default_port(self.auroraCluster)

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
