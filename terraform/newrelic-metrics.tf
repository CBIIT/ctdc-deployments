module "new_relic_metric_pipeline" {
  count                    = var.create_newrelic_pipeline ? 1 : 0
  source                   = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/firehose-metrics?ref=v1.0"
  account_id               = data.aws_caller_identity.current.account_id
  app                      = var.project
  http_endpoint_access_key = var.newrelic_api_key
  level                    = var.account_level
  new_relic_account_id     = var.newrelic_account_id
  permission_boundary_arn  = local.permissions_boundary
  program                  = var.program
  s3_bucket_arn            = var.newrelic_s3_bucket
}