# vars
variable "sumologic_access_id" {
  type        = string
  description = "Sumo Logic Access ID"
}
variable "sumologic_access_key" {
  type        = string
  description = "Sumo Logic Access Key"
  sensitive   = true
}

# modules
module "monitoring" {
  source               = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/monitoring?ref=v1.0"
  app                  = var.stack_name
  tags                 = var.tags
  sumologic_access_id  = var.sumologic_access_id
  sumologic_access_key = var.sumologic_access_key
  microservices        = var.microservices
}