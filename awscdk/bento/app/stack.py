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
from aws_cdk import aws_iam as iam

from services import frontend, backend, files, authn, interoperation
#from services import frontend, authn, backend

class Stack(Stack):
    def __init__(self, scope: Construct, **kwargs) -> None:
        super().__init__(scope, **kwargs)

        # Read config
        config = ConfigParser()
        config.read('config.ini')
        
        self.namingPrefix = "{}-{}".format(config['main']['resource_prefix'], config['main']['tier'])

        # if config.has_option('main', 'subdomain'):
        #     self.app_url = "https://{}.{}".format(config['main']['subdomain'], config['main']['domain'])
        # else:
        #     self.app_url = "https://{}".format(config['main']['domain'])

        if config.has_option('main', 'subdomain'):
            subdomain = config['main']['subdomain']
            tier = config['main']['tier']
            if tier.lower() != "prod":
                subdomain = f"{subdomain}-{tier}"
            self.app_url = f"https://{subdomain}.{config['main']['domain']}"
        else:
            self.app_url = f"https://{config['main']['domain']}"
        
        # Import VPC
        self.VPC = ec2.Vpc.from_lookup(self, "VPC",
            vpc_id=config['main']['vpc_id']
        )

        # Determine VPC and subnet usage for OpenSearch
        if config['os']['endpoint_type'] == 'vpc':
            vpc = self.VPC
            vpc_subnets = [ec2.SubnetSelection(subnets=[self.VPC.isolated_subnets[0]])]
        else:
            vpc = None
            vpc_subnets = [{}]


        # OpenSearch Domain
        self.osDomain = opensearch.Domain(
            self,
            "opensearch",
            version=opensearch.EngineVersion.open_search(config['os']['version']),
            removal_policy=RemovalPolicy.DESTROY,
            zone_awareness=opensearch.ZoneAwarenessConfig(enabled=False),
            capacity=opensearch.CapacityConfig(
                data_node_instance_type=config['os']['data_node_instance_type'],
                multi_az_with_standby_enabled=False
            ),
            vpc=vpc,
            vpc_subnets=[ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                availability_zones=[vpc.availability_zones[0]]
            )],
            enforce_https=True,
            node_to_node_encryption=True,
        )

        # Policy to allow access for dataloader instances
        os_policy = iam.PolicyStatement(
            actions=[
                "es:ESHttpGet",
                "es:ESHttpPut",
                "es:ESHttpPost",
                "es:ESHttpPatch",
                "es:ESHttpHead",
                "es:ESHttpGet",
                "es:ESHttpDelete",
            ],
            resources=[f"{self.osDomain.domain_arn}/*"],
            principals=[iam.AnyPrincipal()],
        )
        self.osDomain.add_access_policies(os_policy)

        if config.has_option('os', 'opensearch_allowed_ips'):
            ip_cidrs = [ip.strip() for ip in config['os']['opensearch_allowed_ips'].split(',')]
            for ip in ip_cidrs:
                self.osDomain.connections.allow_from(ec2.Peer.ipv4(ip), ec2.Port.HTTPS)
        
        # Cloudfront
        # self.cfOrigin = s3.Bucket(self, "CFBucket",
        #     removal_policy=RemovalPolicy.DESTROY
        # )

        self.cfOrigin = s3.Bucket.from_bucket_name(self, "CFBucket",
            bucket_name=config['s3']['file_manifest_bucket_name']
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
        
        # # RDS
        self.auroraCluster = rds.DatabaseCluster(self, "Aurora",
            engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_05_2),
            writer=rds.ClusterInstance.provisioned("writer",
            ),
            vpc=vpc,
            storage_encrypted=True,
            default_database_name=config['db']['mysql_database']
        )

        # Secrets
        self.secret = secretsmanager.Secret(self, "Secret",
            secret_name="{}/{}/{}".format(config['main']['secret_prefix'], config['main']['tier'], "ctdc"),
            secret_object_value={
                "file_manifest_bucket_name": SecretValue.unsafe_plain_text(config['s3']['file_manifest_bucket_name']),
                "es_host": SecretValue.unsafe_plain_text(self.osDomain.domain_endpoint),
                "cf_key_pair_id": SecretValue.unsafe_plain_text(CFPublicKey.public_key_id),
                "cf_url": SecretValue.unsafe_plain_text("https://{}".format(self.cfDistribution.distribution_domain_name)),
                "cookie_secret": SecretValue.unsafe_plain_text(config['secrets']['cookie_secret']),
                "dcf_client_id": SecretValue.unsafe_plain_text(config['secrets']['dcf_client_id']),
                "dcf_client_secret": SecretValue.unsafe_plain_text(config['secrets']['dcf_client_secret']),
                "dcf_base_url": SecretValue.unsafe_plain_text(config['secrets']['dcf_base_url']),
                "dcf_redirect_url": SecretValue.unsafe_plain_text(config['secrets']['dcf_redirect_url']),
                "dcf_userinfo_url": SecretValue.unsafe_plain_text(config['secrets']['dcf_userinfo_url']),
                "dcf_authorize_url": SecretValue.unsafe_plain_text(config['secrets']['dcf_authorize_url']),
                "dcf_token_url": SecretValue.unsafe_plain_text(config['secrets']['dcf_token_url']),
                "dcf_logout_url": SecretValue.unsafe_plain_text(config['secrets']['dcf_logout_url']),
                "dcf_scope": SecretValue.unsafe_plain_text(config['secrets']['dcf_scope']),
                "dcf_prompt": SecretValue.unsafe_plain_text(config['secrets']['dcf_prompt']),
                "dcf_file_url": SecretValue.unsafe_plain_text(config['secrets']['dcf_file_url']),
                "google_id": SecretValue.unsafe_plain_text(config['secrets']['google_id']),
                "s3_access_key_id": SecretValue.unsafe_plain_text(config['secrets']['s3_access_key_id']),
                "s3_secret_access_key": SecretValue.unsafe_plain_text(config['secrets']['s3_secret_access_key']),
                "react_app_data_model_navigator": SecretValue.unsafe_plain_text(config['secrets']['react_app_data_model_navigator']),
            }
        )

        # ALB
        self.ALB = elbv2.ApplicationLoadBalancer(self,
            "alb",
            vpc=self.VPC,
            internet_facing=config.getboolean('alb', 'internet_facing'),
            vpc_subnets=ec2.SubnetSelection(
                subnets=self.VPC.select_subnets(one_per_az=True, subnet_type=ec2.SubnetType.PUBLIC).subnets
            )
        )

        self.ALB.log_access_logs(
            prefix=f"{config['main']['program']}/{config['main']['tier']}/{config['main']['project']}/alb-access-logs",
            bucket=s3.Bucket.from_bucket_arn(self,
                f"{self.namingPrefix}-ALB-CentralLogBucket",
                bucket_arn=config['alb']['log_bucket_arn']
            )
        )

        self.ALB.add_redirect(
            source_protocol=elbv2.ApplicationProtocol.HTTP,
            source_port=80,
            target_protocol=elbv2.ApplicationProtocol.HTTPS,
            target_port=443
        )

        alb_cert = cfm.Certificate.from_certificate_arn(self, "alb-cert",
            certificate_arn=config['alb']['certificate_arn']
        )
        
        self.listener = self.ALB.add_listener("PublicListener",
            certificates=[alb_cert],
            port=443
        )

        self.app_url = f"https://{self.ALB.load_balancer_dns_name}"

        # ECS Cluster
        self.kmsKey = kms.Key(self, "ECSExecKey")

        self.ECSCluster = ecs.Cluster(self,
            "ecs",
            vpc=self.VPC,
            execute_command_configuration=ecs.ExecuteCommandConfiguration(
                kms_key=self.kmsKey
            ),
        )

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

        self.listener.add_action("ECS-Content-Not-Found",
            action=elbv2.ListenerAction.fixed_response(200,
                message_body="The requested resource is not available")
        )