import boto3
import requests
import os
import argparse
from kvswebrtc.kvswebrtc_stack import KvsWebRtcStack

# Function to get stack output
def get_stack_output(stack_name, output_key):
    cfn_client = boto3.client('cloudformation')
    response = cfn_client.describe_stacks(StackName=stack_name)
    outputs = response['Stacks'][0]['Outputs']
    for output in outputs:
        if output['OutputKey'] == output_key:
            return output['OutputValue']
    return None

# Function to download AWS IoT Root CA
def download_root_ca(output_dir):
    root_ca_url = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"
    response = requests.get(root_ca_url, timeout=(10, 20))
    if response.status_code == 200:
        root_ca_path = os.path.join(output_dir, "rootca.pem")
        with open(root_ca_path, "w", encoding="utf-8") as f:
            f.write(response.text)
        print(f"AWS IoT Root CA downloaded to {root_ca_path}")
    else:
        print("Failed to download AWS IoT Root CA.")

def get_iot_credential_provider_endpoint():
    iot_client = boto3.client('iot')
    response = iot_client.describe_endpoint(endpointType='iot:CredentialProvider')
    return response['endpointAddress']

def create_env_file(output_dir, iot_credential_provider, thing_name, 
                    role_alias, cert_file, key_file, root_ca,
                    signaling_channel_arn, signaling_channel_name,
                    aws_default_region):
    env_path = os.path.join(output_dir, ".env")
    with open(env_path, "w", encoding="utf-8") as f:
        f.write(f"IOT_CREDENTIAL_PROVIDER={iot_credential_provider}\n")
        f.write(f"THING_NAME={thing_name}\n")
        f.write(f"ROLE_ALIAS={role_alias}\n")
        f.write(f"CERT_FILE={cert_file}\n")
        f.write(f"KEY_FILE={key_file}\n")
        f.write(f"ROOT_CA={root_ca}\n")
        f.write(f"SIGNALING_CHANNEL_ARN={signaling_channel_arn}\n")
        f.write(f"SIGNALING_CHANNEL_NAME={signaling_channel_name}\n")
        f.write(f"AWS_DEFAULT_REGION={aws_default_region}\n")
    print(f".env file created at {env_path}")

def main():
    parser = argparse.ArgumentParser(description='Download IoT device Certs and envrionment variable')
    parser.add_argument('--output-dir', type=str, default="script-output", help='download location')
    args = parser.parse_args()

    output_dir = args.output_dir
    stack_name = "KvsWebRtcStack"
    thing_name = get_stack_output(stack_name, "ThingName")
    role_alias = get_stack_output(stack_name, "RoleAlias")
    certificate_pem = get_stack_output(stack_name, "CertificatePem")
    private_key = get_stack_output(stack_name, "PrivateKey")
    signaling_channel_arn = get_stack_output(stack_name, "SignalingChannelArn")
    signaling_channel_name = get_stack_output(stack_name, "SignalingChannelName")
    aws_default_region = os.environ.get('AWS_DEFAULT_REGION', 'us-west-2')
    
    if certificate_pem and private_key and role_alias:
        KvsWebRtcStack.write_certificate_files(output_dir, certificate_pem, private_key)
        # Download the AWS IoT Root CA
        script_output_dir = os.path.join(os.getcwd(), output_dir)
        download_root_ca(script_output_dir)

        # Create .env file
        iot_credential_provider_endpoint = get_iot_credential_provider_endpoint()
        create_env_file(
            script_output_dir,
            iot_credential_provider_endpoint,
            thing_name,
            role_alias,
            "device.cert.pem",
            "device.private.key",
            "rootca.pem",
            signaling_channel_arn,
            signaling_channel_name,
            aws_default_region
        )
    else:
        print("Failed to retrieve certificate information from stack outputs.")

if __name__ == '__main__':
    main()