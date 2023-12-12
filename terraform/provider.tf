terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">=4.0.0, <=4.66.1"
    }
  }
}

provider "aws" {
  region = var.region
}