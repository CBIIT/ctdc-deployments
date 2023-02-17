# data
data "aws_iam_policy_document" "s3_alb_policy" {
  statement {
    sid    = "allowalbaccount"
    effect = "Allow"
    principals {
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
      type        = "AWS"
    }
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${module.s3.bucket_name}/*"]
  }
  statement {
    sid    = "allowalblogdelivery"
    effect = "Allow"
    principals {
      identifiers = ["delivery.logs.amazonaws.com"]
      type        = "Service"
    }
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${module.s3.bucket_name}/*"]
    condition {
      test     = "StringEquals"
      values   = ["bucket-owner-full-control"]
      variable = "s3:x-amz-acl"
    }
  }
  statement {
    sid       = "awslogdeliveryacl"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:aws:s3:::${module.s3.bucket_name}"]
    principals {
      identifiers = ["delivery.logs.amazonaws.com"]
      type        = "Service"
    }
  }
}

# s3 resources
resource "aws_s3_bucket_policy" "alb_bucket_policy" {
  bucket = module.s3.bucket_id
  policy = data.aws_iam_policy_document.s3_alb_policy.json
}
