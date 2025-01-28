import boto3
from configparser import ConfigParser
from constructs import Construct
from cdk_ec2_key_pair import KeyPair, PublicKeyFormat

from aws_cdk import Stack, RemovalPolicy, SecretValue, Duration
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_opensearchservice as opensearch
from aws_cdk import aws_kms as kms
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_certificatemanager as cfm
from aws_cdk import aws_rds as rds
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_ssm as ssm

from services import frontend, backend, files, authn, interoperation

class Stack(Stack):
    def __init__(self, scope: Construct, **kwargs) -> None:
        super().__init__(scope, **kwargs)

        # Read config
        config = ConfigParser()
        config.read('config.ini')
        
        self.namingPrefix = "{}-{}".format(config['main']['resource_prefix'], config['main']['tier'])

        if config.has_option('main', 'subdomain'):
            self.app_url = "https://{}.{}".format(config['main']['subdomain'], config['main']['domain'])
        else:
            self.app_url = "https://{}".format(config['main']['domain'])
        
        # Import VPC
        self.VPC = ec2.Vpc.from_lookup(self, "VPC",
            vpc_id=config['main']['vpc_id']
        )

        # Opensearch Cluster
        if config['os']['endpoint_type'] == 'vpc':
            vpc = self.VPC
            vpc_subnets = [{'subnets': [self.VPC.private_subnets[0]]}]
        else:
            vpc = None
            vpc_subnets = [{}]

        self.osDomain = opensearch.Domain(self,
            "opensearch",
            version=opensearch.EngineVersion.open_search(config['os']['version']),
            vpc=vpc,
            zone_awareness=opensearch.ZoneAwarenessConfig(enabled=False),
            capacity=opensearch.CapacityConfig(
                data_node_instance_type=config['os']['data_node_instance_type'],
                multi_az_with_standby_enabled=False
            ),
            vpc_subnets=vpc_subnets,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Cloudfront
        self.cfOrigin = s3.Bucket(self, "CFBucket",
            removal_policy=RemovalPolicy.DESTROY
        )

        self.cfKeys = KeyPair(self, "CFKeyPair",
            key_pair_name="CF-key-{}-{}".format(config['main']['resource_prefix'], config['main']['tier']),
            expose_public_key=True,
            public_key_format=PublicKeyFormat.PEM
        )

        CFPublicKey = cloudfront.PublicKey(self, "CFPublicKey-{}".format(config['main']['tier']),
            encoded_key=self.cfKeys.public_key_value
        )
        CFKeyGroup = cloudfront.KeyGroup(self, "CFKeyGroup-{}".format(config['main']['tier']),
            items=[CFPublicKey]
        )
        
        self.cfDistribution = cloudfront.Distribution(self, "CFDistro",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(self.cfOrigin),
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
                trusted_key_groups=[CFKeyGroup]
            )
        )
        
        # RDS Instance
        self.auroraInstance = rds.DatabaseInstance(self, "AuroraInstance",
            engine=rds.DatabaseInstanceEngine.mysql(
                version=rds.MysqlEngineVersion.VER_8_0_30
            ),
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE2,
                ec2.InstanceSize.MEDIUM
            ),
            vpc=vpc,
            credentials=rds.Credentials.from_username(config['db']['mysql_user']),
            database_name=config['db']['mysql_database'],
            allocated_storage=100,
            backup_retention=Duration.days(7),
            deletion_protection=False,
            publicly_accessible=False
        )

        # Secrets
        self.secret = secretsmanager.Secret(self, "Secret",
            secret_name="{}/{}/{}".format(config['main']['secret_prefix'], config['main']['tier'], "ctdc"),
            secret_object_value={
                "neo4j_user": SecretValue.unsafe_plain_text(config['db']['neo4j_user']),
                "neo4j_password": SecretValue.unsafe_plain_text(config['db']['neo4j_password']),
                "es_host": SecretValue.unsafe_plain_text(self.osDomain.domain_endpoint),
                "cf_key_pair_id": SecretValue.unsafe_plain_text(CFPublicKey.public_key_id),
                "cf_url": SecretValue.unsafe_plain_text("https://{}".format(self.cfDistribution.distribution_domain_name)),
                "cookie_secret": SecretValue.unsafe_plain_text(config['secrets']['cookie_secret']),
                "token_secret": SecretValue.unsafe_plain_text(config['secrets']['token_secret']),
                "email_user": SecretValue.unsafe_plain_text(config['secrets']['email_user']),
                "email_password": SecretValue.unsafe_plain_text(config['secrets']['email_password']),
                "google_client_id": SecretValue.unsafe_plain_text(config['secrets']['google_client_id']),
                "google_client_secret": SecretValue.unsafe_plain_text(config['secrets']['google_client_secret']),
                "nih_client_id": SecretValue.unsafe_plain_text(config['secrets']['nih_client_id']),
                "nih_client_secret": SecretValue.unsafe_plain_text(config['secrets']['nih_client_secret']),
            }
        )

        # ALB
        if config.getboolean('alb', 'internet_facing'):
            subnets = ec2.SubnetSelection(
                subnets=vpc.select_subnets(one_per_az=True, subnet_type=ec2.SubnetType.PUBLIC).subnets
            )
        else:
            subnets = ec2.SubnetSelection(
                subnets=vpc.select_subnets(one_per_az=True, subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnets
            )
    
        self.ALB = elbv2.ApplicationLoadBalancer(self,
            "alb",
            vpc=self.VPC,
            internet_facing=config.getboolean('alb', 'internet_facing'),
            vpc_subnets=subnets
        )

        self.ALB.add_redirect(
            source_protocol=elbv2.ApplicationProtocol.HTTP,
            source_port=80,
            target_protocol=elbv2.ApplicationProtocol.HTTPS,
            target_port=443
        )

        client = boto3.client('acm')
        response = client.list_certificates(CertificateStatuses=['ISSUED'])

        for cert in response["CertificateSummaryList"]:
            if ('*.{}'.format(config['main']['domain']) in cert.values()):
                certARN = cert['CertificateArn']

        alb_cert = cfm.Certificate.from_certificate_arn(self, "alb-cert",
            certificate_arn=certARN)
        
        self.listener = self.ALB.add_listener("PublicListener",
            certificates=[alb_cert],
            port=443
        )

        self.listener.add_action("ECS-Content-Not-Found",
            action=elbv2.ListenerAction.fixed_response(200,
                message_body="The requested resource is not available")
        )

        # ECS Cluster
        self.kmsKey = kms.Key(self, "ECSExecKey")

        self.ECSCluster = ecs.Cluster(self,
            "ecs",
            vpc=self.VPC,
            execute_command_configuration=ecs.ExecuteCommandConfiguration(
                kms_key=self.kmsKey
            ),
        )

        # Fargate Services
        frontend.frontendService.createService(self, config)
        backend.backendService.createService(self, config)
        authn.authnService.createService(self, config)
        files.filesService.createService(self, config)
        interoperation.interoperationService.createService(self, config)

        ### Fargate
        # Frontend Service
        frontend.frontendService.createService(self, config)

        # Backend Service
        backend.backendService.createService(self, config)

        # AuthN Service
        authn.authnService.createService(self, config)

        # AuthZ Service
        #authz.authzService.createService(self, config)

        # Files Service
        files.filesService.createService(self, config)

        # Interoperation Service
        interoperation.interoperationService.createService(self, config)