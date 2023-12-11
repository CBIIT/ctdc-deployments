resource "aws_s3_bucket_policy" "s3_snapshot_policy" {
  count  = terraform.workspace == "stage" ? 1 : 0
  bucket = module.s3[0].bucket_id
  policy = data.aws_iam_policy_document.s3bucket_policy[0].json
}