from aws_cdk import Duration

from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_ecr as ecr
from aws_cdk import aws_secretsmanager as secretsmanager

class backendService:
  def createService(self, config):

    ### Backend Service ###############################################################################################################
    service = "backend"

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
            # "NEW_RELIC_LOG_FILE_NAME":"STDOUT",
            # "JAVA_OPTS": "-javaagent:/usr/local/tomcat/newrelic/newrelic.jar",
            "AUTH_ENABLED":"false",
            "AUTH_ENDPOINT":"/api/auth/",
            "BENTO_API_VERSION":config[service]['image'],
            "MYSQL_SESSION_ENABLED":"true",
            "NEO4J_URL":"bolt://{}:7687".format(config['db']['neo4j_ip']),
            "REDIS_ENABLE":"false",
            "REDIS_FILTER_ENABLE":"false",
            "REDIS_HOST":"localhost",
            "REDIS_PORT":"6379",
            "REDIS_USE_CLUSTER":"true",
        }

    secrets={
            # "NEW_RELIC_LICENSE_KEY":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "be_newrelic", secret_name='monitoring/newrelic'), 'api_key'),
            "NEO4J_PASSWORD":ecs.Secret.from_secrets_manager(self.secret, 'neo4j_password'),
            "NEO4J_USER":ecs.Secret.from_secrets_manager(self.secret, 'neo4j_user'),
            "ES_HOST":ecs.Secret.from_secrets_manager(secretsmanager.Secret.from_secret_name_v2(self, "es_host_{}".format(service), secret_name='bento/bento/perf'), 'es_host'),
            # "ES_HOST":ecs.Secret.from_secrets_manager(self.secret, 'es_host'),
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
        port_mappings=[ecs.PortMapping(app_protocol=ecs.AppProtocol.http, container_port=config.getint(service, 'port'), name=service)],
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
