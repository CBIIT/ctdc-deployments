module "alb" {
  source              = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/loadbalancer?ref=v1.0"
  vpc_id              = var.vpc_id
  alb_log_bucket_name = module.s3.bucket_name
  env                 = terraform.workspace
  alb_internal        = var.internal_alb
  alb_type            = var.lb_type
  #alb_subnet_ids      = local.alb_subnet_ids
  alb_subnet_ids      = var.private_subnet_ids
  tags                = var.tags
  stack_name          = var.project
  alb_certificate_arn = data.aws_acm_certificate.amazon_issued.arn
}

module "s3" {
  source                        = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/s3?ref=v1.0"
  bucket_name                   = local.alb_log_bucket_name
  stack_name                    = var.project
  env                           = terraform.workspace
  tags                          = var.tags
  s3_force_destroy              = var.s3_force_destroy
  days_for_archive_tiering      = 125
  days_for_deep_archive_tiering = 180
  s3_enable_access_logging      = false
  s3_access_log_bucket_id       = ""
}