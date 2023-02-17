locals {
  bastion_port                    = 22
  http_port                       = 80
  any_port                        = 0
  any_protocol                    = "-1"
  tcp_protocol                    = "tcp"
  https_port                      = "443"
  neo4j_http                      = 7474
  neo4j_https                     = 7473
  neo4j_bolt                      = 7687
  integration_server_profile_name = "${var.iam_prefix}-integration-server-profile"
  permissions_boundary            = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/PermissionBoundary_PowerUser"
  #nih_ip_cidrs =  terraform.workspace == "prod" || terraform.workspace == "stage" ? ["0.0.0.0/0"] : [ "129.43.0.0/16" , "137.187.0.0/16"  , "165.112.0.0/16" , "156.40.0.0/16"  , "128.231.0.0/16" , "130.14.0.0/16" , "157.98.0.0/16"]
  nih_ip_cidrs = ["0.0.0.0/0"]
  all_ips      =  local.nih_ip_cidrs
  #allowed_alb_ip_range = terraform.workspace == "prod" || terraform.workspace == "stage" ?  local.all_ips : local.nih_ip_cidrs
  allowed_alb_ip_range         = local.nih_ip_cidrs
  fargate_security_group_ports = ["443", "3306", "7473", "7474", "7687"]
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess"
  ]
}
