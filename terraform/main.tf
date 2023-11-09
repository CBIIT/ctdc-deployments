# ALB
module "alb" {
  source              = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/loadbalancer?ref=v1.9"
  resource_prefix     = "${var.program}-${terraform.workspace}-${var.project}"
  vpc_id              = var.vpc_id
  env                 = terraform.workspace
  alb_internal        = var.internal_alb
  alb_type            = var.lb_type
  #alb_subnet_ids      = local.alb_subnet_ids
  alb_subnet_ids      = var.private_subnet_ids
  tags                = var.tags
  stack_name          = var.project
  program             = "crdc"
  alb_certificate_arn = data.aws_acm_certificate.amazon_issued.arn
}

# Cloudfront
module "cloudfront" {
  count                               = var.create_cloudfront ? 1 : 0
  source                              = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/cloudfront?ref=v1.9"
  resource_prefix                     = "${var.program}-${terraform.workspace}-${var.project}"
  alarms                              = var.alarms
  domain_name                         = var.domain_name
  cloudfront_distribution_bucket_name = var.cloudfront_distribution_bucket_name
  cloudfront_slack_channel_name       = var.cloudfront_slack_channel_name
  env                                 = terraform.workspace
  stack_name                          = var.project
  slack_secret_name                   = var.slack_secret_name
  tags                                = var.tags
  create_files_bucket                 = var.create_files_bucket
  target_account_cloudone             = var.target_account_cloudone
  public_key_path                     = file("${path.module}/workspace/ctdc_public_key.pem")
}

# ECS
module "ecs" {
  source                    = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/ecs?ref=v1.9"
  stack_name                = var.project
  resource_prefix           = "${var.program}-${terraform.workspace}-${var.project}"
  tags                      = var.tags
  vpc_id                    = var.vpc_id
  add_opensearch_permission = var.add_opensearch_permission
  ecs_subnet_ids            = var.private_subnet_ids
  application_url           = local.application_url
  env                       = terraform.workspace
  microservices             = var.microservices
  alb_https_listener_arn    = module.alb.alb_https_listener_arn
  target_account_cloudone   = var.target_account_cloudone
  allow_cloudwatch_stream   = var.allow_cloudwatch_stream
  central_ecr_account_id    = var.central_ecr_account_id
}

# Monitoring
module "monitoring" {
  source               = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/monitoring?ref=v1.9"
  app                  = var.project
  tags                 = var.tags
  sumologic_access_id  = var.sumologic_access_id
  sumologic_access_key = var.sumologic_access_key
  microservices        = var.microservices
  service              = var.service
  program              = var.program
  newrelic_account_id  = var.newrelic_account_id
  newrelic_api_key     = var.newrelic_api_key
  resource_prefix      = "${var.program}-${terraform.workspace}-${var.project}"
}

# Newrelic
module "new_relic_metric_pipeline" {
  count                    = var.create_newrelic_pipeline ? 1 : 0
  source                   = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/firehose-metrics?ref=v1.9"
  account_id               = data.aws_caller_identity.current.account_id
  app                      = var.project
  http_endpoint_access_key = var.newrelic_api_key
  level                    = var.account_level
  new_relic_account_id     = var.newrelic_account_id
  permission_boundary_arn  = local.permissions_boundary
  program                  = var.program
  s3_bucket_arn            = var.newrelic_s3_bucket
  resource_prefix          = "${var.program}-${var.project}-${var.account_level}"
}

# Opensearch
module "opensearch" {
  count                             = var.create_opensearch_cluster ? 1 : 0
  source                            = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/opensearch?ref=v1.9"
  stack_name                        = var.project
  resource_prefix                   = "${var.program}-${terraform.workspace}-${var.project}"
  tags                              = var.tags
  opensearch_instance_type          = var.opensearch_instance_type
  env                               = terraform.workspace
  opensearch_subnet_ids             = var.private_subnet_ids
  opensearch_version                = var.opensearch_version
  automated_snapshot_start_hour     = var.automated_snapshot_start_hour
  opensearch_ebs_volume_size        = var.opensearch_ebs_volume_size
  opensearch_instance_count         = var.opensearch_instance_count
  opensearch_log_types              = ["INDEX_SLOW_LOGS"]
  create_os_service_role            = var.create_os_service_role
  multi_az_enabled                  = var.multi_az_enabled
  vpc_id                            = var.vpc_id
  opensearch_autotune_rollback_type = "NO_ROLLBACK"
  create_cloudwatch_log_policy      = var.create_cloudwatch_log_policy
}

#mysql
module "rds_mysql" {
  count                        = var.create_rds_mysql ? 1 : 0
  source                       = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/rds-mysql?ref=mysql"   #ref needs to changed after the tag is created.

  program                      = var.program
  app                          = var.project
  env                          = terraform.workspace
  resource_prefix              = "${var.program}-${terraform.workspace}-${var.project}"
  allocated_storage            = var.rds_allocated_storage
  attach_permissions_boundary  = local.level == "nonprod" ? true : false
  create_db_subnet_group       = var.create_rds_db_subnet_group
  create_security_group        = var.create_rds_security_group
  db_name                      = var.project
  instance_class               = var.rds_instance_class
  username                     = var.rds_username
  password                     = random_password.rds_password[0].result
  subnet_ids                   = var.private_subnet_ids
  vpc_id                       = data.aws_vpc.vpc.id
}

resource "random_password" "rds_password" {
  count                        = var.create_rds_mysql ? 1 : 0
  length                       = 12
  special                      = true
  override_special             = "!#$%^&*()-_=+[]{}<>:?"
  keepers = {
    keep = true
  }
}

# Secrets
module "deepmerge" {
  source = "Invicton-Labs/deepmerge/null"
  maps = [
    local.dynamic_secrets,
    var.secret_values
  ]
}

module "secrets" {
  source        = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/secrets?ref=v1.9"
  app           = var.project
  secret_values = module.deepmerge.merged
  #secret_values = var.secret_values
}
