module "deepmerge" {
  source = "Invicton-Labs/deepmerge/null"
  maps = [
    local.dynamic_secrets,
    var.secret_values
  ]
}

module "secrets" {
  source        = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/secrets?ref=v1.0"
  app           = var.project
  secret_values = module.deepmerge.merged
  #secret_values = var.secret_values
}