import os
import boto3
from datetime import datetime, timezone, timedelta

# Retrieve the temporary credentials using AWS CLI
sts = boto3.client('sts')
response = sts.get_session_token()

access_key = response['Credentials']['AccessKeyId']
secret_key = response['Credentials']['SecretAccessKey']
session_token = response['Credentials']['SessionToken']
expiration = response['Credentials']['Expiration']
aws_default_region = os.environ.get('AWS_DEFAULT_REGION', 'us-west-2')

if access_key and secret_key and session_token and expiration:
    # Convert the expiration time to datetime object
    expiration_time = expiration.replace(tzinfo=timezone.utc)
    now = datetime.now(tz=timezone.utc)
    duration = expiration_time - now
    duration_seconds = int(duration.total_seconds())

    # Display the temporary credentials in the desired format
    print(f"\nThis is the temporary credential valid for {duration_seconds} seconds.\nPaste them in your shell!\n")
    print(f"export AWS_ACCESS_KEY_ID={access_key}")
    print(f"export AWS_SECRET_ACCESS_KEY={secret_key}")
    print(f"export AWS_SESSION_TOKEN={session_token}\n")
    print(f"export AWS_DEFAULT_REGION={aws_default_region}\n")
else:
    print("Fail to get temporary credentials.")