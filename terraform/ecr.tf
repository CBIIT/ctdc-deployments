module "ecr" {
  count                    = var.create_ecr_repos ? 1 : 0
  source                   = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/ecr?ref=v1.0"
  project                  = var.project
  env                      = terraform.workspace
  resource_prefix          = local.resource_prefix
  ecr_repo_names           = var.ecr_repo_names
  tags                     = var.tags
  create_env_specific_repo = var.create_env_specific_repo
}