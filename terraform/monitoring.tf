module "monitoring" {
  source               = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/monitoring?ref=v1.0"
  app                  = var.project
  tags                 = var.tags
  sumologic_access_id  = var.sumologic_access_id
  sumologic_access_key = var.sumologic_access_key
  microservices        = var.microservices
}