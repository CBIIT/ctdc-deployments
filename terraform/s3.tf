resource "aws_s3_bucket_policy" "opensearch_snapshot_policy" {
  count  = terraform.workspace == "stage" ? 1 : 0
  bucket = module.s3.bucket_id
  policy = data.aws_iam_policy_document.s3_snapshotbucket_policy.json
}