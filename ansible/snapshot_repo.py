import boto3
import requests
from requests_aws4auth import AWS4Auth

host = 'https://vpc-crdc-dev-ctdc-opensearch-xpy6punggcm65ycvkw2xx63lwy.us-east-1.es.amazonaws.com/' # domain endpoint with trailing /
region = 'us-east-1' # e.g. us-west-1
service = 'es'
credentials = boto3.Session().get_credentials()
awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)

# Register repository

path = '_snapshot/ctdc' # the OpenSearch API endpoint
url = host + path

payload = {
  "type": "s3",
  "settings": {
    "bucket": "crdc-stage-ctdc-opensearch-snapshot-bucket",
    "region": "us-east-1",
    "role_arn": "arn:aws:iam::265135454114:role/power-user-crdc-dev-ctdc-opensearch-snapshot"
  }
}

headers = {"Content-Type": "application/json"}

r = requests.put(url, auth=awsauth, json=payload, headers=headers)

print(r.status_code)
print(r.text)