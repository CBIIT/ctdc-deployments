resource "aws_s3_bucket_policy" "s3_snapshot_policy" {
  count  = terraform.workspace == "stage" ? 1 : 0
  bucket = module.s3[0].bucket_id
  policy = data.aws_iam_policy_document.s3bucket_policy[0].json
}

resource "aws_s3_bucket_policy" "s3_neo4jdump_policy" {
  count  = terraform.workspace == "dev" ? 1 : 0
  bucket = module.s3_neo4jdump[0].bucket_id
  policy = data.aws_iam_policy_document.s3_neo4jdump_policy[0].json
}