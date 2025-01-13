terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">=4.66.1"
    }
  }
}

provider "aws" {
  region = var.region
  
  default_tags {
    tags = {
      EnvironmentTier = terraform.workspace
      Customer        = "nci od cbiit ods"
      DevLead         = "yizhen chen"
      CreatedBy       = "Charles Ngu"
      ResourceName    = "NCI-ctdc-${terraform.workspace}"
      FISMA           = "moderate"
      ManagedBy       = "terraform"
      OpsModel        = "cbiit managed hybrid"
      Program         = "crdc"
      PII             = "yes"
      Backup          = local.level
      PatchGroup      = local.level
      ApplicationName = "Clinical and Translational Data Commons"
      ProjectManager  = "Hayley Dingerdissen"
    }
  }
}