# locals
locals {
  application_url = terraform.workspace == "prod" ? var.domain_name : "${var.application_subdomain}-${terraform.workspace}.${var.domain_name}"
}

# vars
variable "add_opensearch_permission" {
  type        = bool
  default     = false
  description = "choose to create opensearch permission or not"
}

variable "allow_cloudwatch_stream" {
  type        = bool
  default     = true
  description = "allow cloudwatch stream for the containers"
}

variable "application_subdomain" {
  description = "subdomain of the app"
  type        = string
}

# modules
module "ecs" {
  source                    = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/ecs?ref=ctdc_prod_terraform"
  stack_name                = var.stack_name
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
}