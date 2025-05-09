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
from aws_cdk import aws_iam as iam

from services import frontend, backend, files, authn, interoperation

class Stack(Stack):
    def __init__(self, scope: Construct, **kwargs) -> None:
        super().__init__(scope, **kwargs)

        config = ConfigParser()
        config.read('config.ini')
        
        self.namingPrefix = "{}-{}".format(config['main']['resource_prefix'], config['main']['tier'])

        self.app_url = f"https://{config['main'].get('subdomain') + '.' if config['main'].get('subdomain') else ''}{config['main']['domain']}"

        self.VPC = ec2.Vpc.from_lookup(self, "VPC",
            vpc_id=config['main']['vpc_id']
        )

        # Security Groups
        self.albSG = ec2.SecurityGroup(self, "ALBSG",
            vpc=self.VPC,
            allow_all_outbound=True,
            description="Allow HTTP/HTTPS traffic"
        )

        self.backendSG = ec2.SecurityGroup(self, "BackendSG",
            vpc=self.VPC,
            allow_all_outbound=True,
            description="Allow ALB to talk to backend on port 8080"
        )

        self.backendSG.add_ingress_rule(
            peer=self.albSG,
            connection=ec2.Port.tcp(8080),
            description="Allow ALB to reach backend"
        )

        self.osSG = ec2.SecurityGroup(self, "OSSG",
            vpc=self.VPC,
            allow_all_outbound=True,
            description="Allow backend and IP whitelist to access OpenSearch"
        )

        self.osSG.add_ingress_rule(
            peer=self.backendSG,
            connection=ec2.Port.tcp(443),
            description="Allow backend SG to access OpenSearch"
        )

        whitelist_ips = [ip.strip() for ip in config['main']['ec2_whitelist_ips'].split(",")]
        for ip in whitelist_ips:
            self.osSG.add_ingress_rule(
                peer=ec2.Peer.ipv4(ip),
                connection=ec2.Port.tcp(443),
                description=f"Allow whitelisted IP {ip} to access OpenSearch"
            )

        # OpenSearch
        self.osDomain = opensearch.Domain(self,
            "opensearch",
            version=opensearch.EngineVersion.open_search(config['os']['version']),
            vpc=self.VPC,
            security_groups=[self.osSG],
            zone_awareness=opensearch.ZoneAwarenessConfig(enabled=False),
            capacity=opensearch.CapacityConfig(
                data_node_instance_type=config['os']['data_node_instance_type'],
                multi_az_with_standby_enabled=False
            ),
            vpc_subnets=[{"subnet_type": ec2.SubnetType.PRIVATE_WITH_EGRESS}],
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Allow access via policy (optional if SG is enough)
        os_policy = iam.PolicyStatement(
            actions=[
                "es:ESHttpGet", "es:ESHttpPut", "es:ESHttpPost",
                "es:ESHttpPatch", "es:ESHttpHead", "es:ESHttpDelete",
            ],
            resources=["{}/*".format(self.osDomain.domain_arn)],
            principals=[iam.AnyPrincipal()],
        )
        self.osDomain.add_access_policies(os_policy)

        # CloudFront
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

        # RDS
        self.auroraCluster = rds.DatabaseCluster(self, "Aurora",
            engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_05_2),
            writer=rds.ClusterInstance.provisioned("writer"),
            vpc=self.VPC,
            storage_encrypted=True,
            default_database_name=config['db']['mysql_database']
        )

        # Secrets
        self.secret = secretsmanager.Secret(self, "Secret",
            secret_name="{}/{}/{}".format(config['main']['secret_prefix'], config['main']['tier'], "ctdc"),
            secret_object_value={
                "neo4j_user": SecretValue.unsafe_plain_text(config['db']['neo4j_user']),
                "neo4j_password": SecretValue.unsafe_plain_text(config['db']['neo4j_password']),
                "file_manifest_bucket_name": SecretValue.unsafe_plain_text(config['s3']['file_manifest_bucket_name']),
                "es_host": SecretValue.unsafe_plain_text(self.osDomain.domain_endpoint),
                "cf_key_pair_id": SecretValue.unsafe_plain_text(CFPublicKey.public_key_id),
                "cf_url": SecretValue.unsafe_plain_text(f"https://{self.cfDistribution.distribution_domain_name}"),
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
        if config.getboolean('alb', 'internet_facing'):
            subnets = ec2.SubnetSelection(
                subnets=self.VPC.select_subnets(one_per_az=True, subnet_type=ec2.SubnetType.PUBLIC).subnets
            )
        else:
            subnets = ec2.SubnetSelection(
                subnets=self.VPC.select_subnets(one_per_az=True, subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnets
            )

        self.ALB = elbv2.ApplicationLoadBalancer(self,
            "alb",
            vpc=self.VPC,
            internet_facing=config.getboolean('alb', 'internet_facing'),
            vpc_subnets=subnets,
            security_group=self.albSG
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

        # ECS Services
        frontend.frontendService.createService(self, config)
        backend.backendService.createService(self, config, self.backendSG)
        authn.authnService.createService(self, config)
        files.filesService.createService(self, config)
        interoperation.interoperationService.createService(self, config)
