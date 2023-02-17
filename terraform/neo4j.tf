# vars
variable "database_instance_type" {
  description = "ec2 instance type to use"
  type        = string
  default     = "t3.large"
}

variable "db_instance_volume_size" {
  description = "volume size of the instances"
  type        = number
  default     = 100
}

variable "db_private_ip" {
  description = "private ip of the db instance"
  type        = string
  default     = "10.0.0.2"
}

variable "db_subnet_id" {
  description = "subnet id to launch db"
  type        = string
  default     = ""
}

variable "public_ssh_key_ssm_parameter_name" {
  description = "name of the ssm parameter holding ssh key content"
  default     = "ssh_public_key"
  type        = string
}

# modules
module "neo4j" {
  count                             = var.create_db_instance ? 1 : 0
  source                            = "git::https://github.com/CBIIT/datacommons-devops.git//terraform/modules/neo4j?ref=v1.0"
  env                               = terraform.workspace
  vpc_id                            = var.vpc_id
  db_subnet_id                      = var.db_subnet_id
  db_instance_volume_size           = var.db_instance_volume_size
  public_ssh_key_ssm_parameter_name = var.public_ssh_key_ssm_parameter_name
  stack_name                        = var.stack_name
  db_private_ip                     = var.db_private_ip
  database_instance_type            = var.database_instance_type
  tags                              = var.tags
}