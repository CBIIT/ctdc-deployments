# vars
variable "alarms" {
  description = "alarms to be configured"
  type        = map(map(string))
}

variable "cloudfront_distribution_bucket_name" {
  description = "specify the name of s3 bucket for cloudfront"
  type        = string
}

variable "cloudfront_log_path_prefix_key" {
  description = "path prefix to where cloudfront send logs to s3 bucket"
  type        = string
  default     = "cloudfront/logs"
}

variable "cloudfront_origin_acess_identity_description" {
  description = "description for OAI"
  type        = string
  default     = "cloudfront origin access identify for s3"
}

variable "cloudfront_slack_channel_name" {
  type        = string
  description = "cloudfront slack name"
}

variable "create_cloudfront" {
  description = "create cloudfront or not"
  type        = bool
  default     = false
}

variable "create_files_bucket" {
  description = "indicate if you want to create files bucket or use existing one"
  type        = bool
  default     = false
}

variable "slack_secret_name" {
  type        = string
  description = "name of cloudfront slack secret"
}

# modules
module "cloudfront" {
  count                               = var.create_cloudfront ? 1 : 0
  source                              = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/cloudfront?ref=v1.0"
  alarms                              = var.alarms
  domain_name                         = var.domain_name
  cloudfront_distribution_bucket_name = var.cloudfront_distribution_bucket_name
  cloudfront_slack_channel_name       = var.cloudfront_slack_channel_name
  env                                 = terraform.workspace
  stack_name                          = var.stack_name
  slack_secret_name                   = var.slack_secret_name
  tags                                = var.tags
  create_files_bucket                 = var.create_files_bucket
  target_account_cloudone             = var.target_account_cloudone
  public_key_path                     = file("${path.module}/workspace/ctdc_public_key.pem")
}