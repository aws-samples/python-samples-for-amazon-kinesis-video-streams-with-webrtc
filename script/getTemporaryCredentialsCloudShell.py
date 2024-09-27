import os
import requests
import json
from datetime import datetime, timezone

# Fetch the temporary credentials
credentials_uri = os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI")
auth_token = os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN")

if credentials_uri and auth_token:
    headers = {"Authorization": auth_token}
    response = requests.get(credentials_uri, headers=headers, timeout=(10, 20))
    response.raise_for_status()
    credentials_data = response.json()

    access_key = credentials_data.get("AccessKeyId")
    secret_key = credentials_data.get("SecretAccessKey")
    session_token = credentials_data.get("Token")
    expiration = credentials_data.get("Expiration")
    aws_default_region = os.environ.get('AWS_DEFAULT_REGION', 'us-west-2')

    if access_key and secret_key and session_token and expiration:
        expiration = expiration.rstrip("Z")  # Remove the "Z" suffix
        expiration_time = datetime.fromisoformat(expiration).replace(tzinfo=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        duration = expiration_time - now
        duration_seconds = int(duration.total_seconds())

        print(f"\nThis is the temporary credential valid for {duration_seconds} seconds.\nPaste them in your shell!\n")
        print(f"export AWS_ACCESS_KEY_ID={access_key}")
        print(f"export AWS_SECRET_ACCESS_KEY={secret_key}")
        print(f"export AWS_SESSION_TOKEN={session_token}\n")
        print(f"export AWS_DEFAULT_REGION={aws_default_region}\n")
else:
    print("AWS_CONTAINER_CREDENTIALS_FULL_URI or AWS_CONTAINER_AUTHORIZATION_TOKEN environment variable not found.")
