# vars
variable "create_ecr_repos" {
  type        = bool
  default     = false
  description = "choose whether to create ecr repos or not"
}

variable "create_env_specific_repo" {
  description = "choose to create environment specific repo. Example bento-dev-frontend"
  type        = bool
  default     = false
}

variable "ecr_repo_names" {
  description = "list of repo names"
  type        = list(string)
}

# modules
module "ecr" {
  count                    = var.create_ecr_repos ? 1 : 0
  source                   = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/ecr?ref=v1.0"
  stack_name               = var.stack_name
  ecr_repo_names           = var.ecr_repo_names
  tags                     = var.tags
  create_env_specific_repo = var.create_env_specific_repo
  env                      = terraform.workspace
}