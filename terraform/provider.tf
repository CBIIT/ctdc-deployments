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
      Customer       = "nci od cbiit ods"
      DevLead        = "yizhen chen"
      DevOps         = "venkatasaikiran kotepalli"
      FISMA          = "moderate"
      ManagedBy      = "terraform"
      OpsModel       = "cbiit managed hybrid"
      Program        = "crdc"
      PII            = "yes"
      Project        = "ctdc"
      ProjectManager = "Hayley Dingerdissen"
    }
  }
}