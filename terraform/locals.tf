locals {
  bastion_port                    = 22
  http_port                       = 80
  any_port                        = 0
  any_protocol                    = "-1"
  tcp_protocol                    = "tcp"
  https_port                      = "443"
  mysql_port                      = 3306
  neo4j_http                      = 7474
  neo4j_https                     = 7473
  neo4j_bolt                      = 7687
  level                              = terraform.workspace == "stage" || terraform.workspace == "prod" ? "prod" : "nonprod"
  integration_server_profile_name = "${var.iam_prefix}-integration-server-profile"
  permissions_boundary            = terraform.workspace == "dev" || terraform.workspace == "qa" ? "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/PermissionBoundary_PowerUser" : null
  #nih_ip_cidrs =  terraform.workspace == "prod" || terraform.workspace == "stage" ? ["0.0.0.0/0"] : [ "129.43.0.0/16" , "137.187.0.0/16"  , "165.112.0.0/16" , "156.40.0.0/16"  , "128.231.0.0/16" , "130.14.0.0/16" , "157.98.0.0/16"]
  nih_ip_cidrs = ["0.0.0.0/0"]
  all_ips      =  local.nih_ip_cidrs
  nih_cidrs               = ["129.43.0.0/16", "137.187.0.0/16", "10.128.0.0/9", "165.112.0.0/16", "156.40.0.0/16", "10.208.0.0/21", "128.231.0.0/16", "130.14.0.0/16", "157.98.0.0/16", "10.133.0.0/16"]
  #allowed_alb_ip_range = terraform.workspace == "prod" || terraform.workspace == "stage" ?  local.all_ips : local.nih_ip_cidrs
  allowed_alb_ip_range         = local.nih_ip_cidrs
  fargate_security_group_ports = ["443", "3306", "7473", "7474", "7687"]
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess"
  ]
  
  #ALB
  alb_subnet_ids      = terraform.workspace == "prod" || terraform.workspace == "stage" ? var.public_subnet_ids : var.private_subnet_ids
  alb_log_bucket_name = terraform.workspace == "prod" || terraform.workspace == "stage" ? "prod-alb-access-logs" : "nonprod-alb-access-logs"
  cert_types          = "IMPORTED"
  
  # ECR
  resource_prefix = var.project
  
  # ECS
  application_url = terraform.workspace == "prod" ? var.domain_name : "${var.application_subdomain}-${terraform.workspace}.${var.domain_name}"
  
  # Secrets
  dynamic_secrets = {
    app = {
      secretKey   = ""
      description = ""
      secretValue = {
        es_host                       = var.create_opensearch_cluster ? module.opensearch[0].opensearch_endpoint : ""
        sumo_collector_token_frontend = module.monitoring.sumo_source_urls.frontend[0]
        sumo_collector_token_backend  = module.monitoring.sumo_source_urls.backend[0]
        sumo_collector_token_files    = module.monitoring.sumo_source_urls.files[0]
        rds_host                      = var.create_rds_mysql ? module.rds_mysql[0].endpoint : ""
        rds_username                  = var.create_rds_mysql ? var.rds_username : ""
        rds_password                  = var.create_rds_mysql ? nonsensitive(random_password.rds_password[0].result): ""
      }
    }
  }
}