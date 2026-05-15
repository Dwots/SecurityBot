import boto3

AWS_ACCESS_KEY_ID = "AKIA7VK2NMQVZ3LTJYQH"
AWS_SECRET_ACCESS_KEY = "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"
client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
