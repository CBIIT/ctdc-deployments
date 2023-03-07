# data
data "aws_acm_certificate" "amazon_issued" {
  domain      = var.certificate_domain_name
  types       = [local.cert_types]
  most_recent = true
}

# locals
locals {
  alb_subnet_ids      = terraform.workspace == "prod" || terraform.workspace == "stage" ? var.public_subnet_ids : var.private_subnet_ids
  alb_log_bucket_name = terraform.workspace == "prod" || terraform.workspace == "stage" ? "prod-alb-access-logs" : "nonprod-alb-access-logs"
  cert_types          = "IMPORTED"
}

# vars
variable "certificate_domain_name" {
  description = "domain name for the ssl cert"
  type        = string
}

variable "internal_alb" {
  description = "is this alb internal?"
  default     = false
  type        = bool
}

variable "lb_type" {
  description = "Type of loadbalancer"
  type        = string
  default     = "application"
}


variable "public_subnet_ids" {
  description = "Provide list of public subnets to use in this VPC. Example 10.0.1.0/24,10.0.2.0/24"
  type        = list(string)
}

variable "s3_force_destroy" {
  description = "force destroy bucket"
  default     = true
  type        = bool
}

# modules
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
  stack_name          = var.stack_name
  alb_certificate_arn = data.aws_acm_certificate.amazon_issued.arn
}

module "s3" {
  source                        = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/s3?ref=v1.0"
  bucket_name                   = local.alb_log_bucket_name
  stack_name                    = var.stack_name
  env                           = terraform.workspace
  tags                          = var.tags
  s3_force_destroy              = var.s3_force_destroy
  days_for_archive_tiering      = 125
  days_for_deep_archive_tiering = 180
  s3_enable_access_logging      = false
  s3_access_log_bucket_id       = ""
}