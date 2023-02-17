# vars
variable "automated_snapshot_start_hour" {
  description = "hour when automated snapshot to be taken"
  type        = number
  default     = 23
}

variable "create_cloudwatch_log_policy" {
  description = "Due cloudwatch log policy limits, this should be option, we can use an existing policy"
  default     = false
  type        = bool
}

variable "create_os_service_role" {
  type        = bool
  default     = false
  description = "change this value to true if running this script for the first time"
}

variable "multi_az_enabled" {
  description = "set to true to enable multi-az deployment"
  type        = bool
  default     = false
}

variable "opensearch_ebs_volume_size" {
  description = "size of the ebs volume attached to the opensearch instance"
  type        = number
  default     = 200
}

variable "opensearch_instance_count" {
  description = "the number of data nodes to provision for each instance in the cluster"
  type        = number
  default     = 1
}

variable "opensearch_instance_type" {
  description = "type of instance to be used to create the elasticsearch cluster"
  type        = string
  default     = "t3.medium.elasticsearch"
}

variable "opensearch_version" {
  type        = string
  description = "specify es version"
  default     = "OpenSearch_1.1"
}

# modules
module "opensearch" {
  count                             = var.create_opensearch_cluster ? 1 : 0
  source                            = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/opensearch?ref=v1.0"
  stack_name                        = var.stack_name
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