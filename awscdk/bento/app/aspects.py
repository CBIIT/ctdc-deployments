import aws_cdk as cdk
import jsii
from constructs import Construct
from configparser import ConfigParser
from aws_cdk import aws_iam as iam

@jsii.implements(cdk.IAspect)
class MyAspect:
    def visit(self, node):
        # Read config file
        config = ConfigParser()
        config.read('config.ini')

        if isinstance(node, iam.CfnRole):
            if config.has_option('iam', 'role_prefix') and config.has_option('main', 'resource_prefix'):
                role_prefix = config['iam']['role_prefix']
                resource_prefix = config['main']['resource_prefix']

                resolved_logical_id = cdk.Stack.of(node).resolve(node.logical_id)

                base_role_name = f"{role_prefix}-{resource_prefix}-{resolved_logical_id}"

                # IAM role names must be <= 64 characters
                if len(base_role_name) > 64:
                    max_id_length = 64 - len(role_prefix) - len(resource_prefix) - 2  # 2 hyphens
                    resolved_logical_id = resolved_logical_id[:max_id_length]
                    base_role_name = f"{role_prefix}-{resource_prefix}-{resolved_logical_id}"

                node.role_name = base_role_name
