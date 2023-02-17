# global variables
variable "stack_name" {
  description = "name of the project"
  type        = string
}

variable "tags" {
  description = "tags to associate with this instance"
  type        = map(string)
}

variable "vpc_id" {
  description = "vpc id to to launch the ALB"
  type        = string
}

variable "region" {
  description = "aws region to use for this resource"
  type        = string
  default     = "us-east-1"
}

variable "private_subnet_ids" {
  description = "Provide list private subnets to use in this VPC. Example 10.0.10.0/24,10.0.11.0/24"
  type        = list(string)
}

variable "microservices" {
  type = map(object({
    name                      = string
    port                      = number
    health_check_path         = string
    priority_rule_number      = number
    image_url                 = string
    cpu                       = number
    memory                    = number
    path                      = list(string)
    number_container_replicas = number
  }))
}

variable "domain_name" {
  description = "domain name for the application"
  type        = string
}

variable "create_opensearch_cluster" {
  description = "choose to create opensearch cluster or not"
  type        = bool
  default     = false
}

variable "create_db_instance" {
  description = "set this value if you want create db instance"
  default     = false
  type        = bool
}

variable "target_account_cloudone" {
  description = "to add check conditions on whether the resources are brought up in cloudone or not"
  type        = bool
  default     = true
}

variable "iam_prefix" {
  type        = string
  default     = "power-user"
  description = "nci iam power user prefix"
}