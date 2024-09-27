from aws_cdk import (
    App,
    Stack,
    aws_iot as iot,
    aws_kinesisvideo as kvs,
    aws_iam as iam,
    custom_resources as cr,
    CfnOutput,
)
from constructs import Construct
import os

class KvsWebRtcStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        THING_NAME="kvs-demo"
        KVS_IAM_ROLE="KvsDemoCertificateBasedIAMRole"
        KVS_IAM_POLICY="KvsDemoIAMPolicy"
        KVS_IOT_ROLE_ALIAS="KvsDemoIoTRoleAlias"
        KVS_IOT_ROLE_ALIAS_POLICY="KvsDemoIoTRoleAliasPolicy"
        SIGNAL_CHANNEL_NAME="kvs-demo-channel"

        # Create an IoT Thing
        iot_thing = iot.CfnThing(self, "MyIoTThing", thing_name=THING_NAME)

        # Create a policy for KVS WebRTC
        kvs_webrtc_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "kinesisvideo:DescribeStream",
                "kinesisvideo:PutMedia",
                "kinesisvideo:TagStream",
                "kinesisvideo:GetDataEndPoint",
                "kinesisvideo:DescribeSignalingChannel",
                "kinesisvideo:CreateSignalingChannel",
                "kinesisvideo:GetSignalingChannelEndpoint",
                "kinesisvideo:DeleteSignalingChannel",
                "kinesisvideo:GetIceServerConfig",
                "kinesisvideo:ConnectAsMaster",
                "kinesisvideo:ConnectAsViewer",
            ],
            resources=["*"],
        )
        kvs_webrtc_policy_document = iam.PolicyDocument(statements=[kvs_webrtc_policy])

        # Create a role for KVS WebRTC
        kvs_webrtc_role = iam.Role(
            self,
            "KvsWebRtcRole",
            role_name=KVS_IAM_ROLE,
            assumed_by=iam.ServicePrincipal("credentials.iot.amazonaws.com"),
            inline_policies={
                KVS_IAM_POLICY: kvs_webrtc_policy_document
            }
        )

        # Create a custom resource to create the certificate and retrieve its content
        certificate_creator = cr.AwsCustomResource(
            self,
            "CertificateCreator",
            on_create=cr.AwsSdkCall(
                service="Iot",
                action="createKeysAndCertificate",
                physical_resource_id=cr.PhysicalResourceId.from_response("certificateId"),
                parameters={
                    "setAsActive": True
                },
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE)
        )

        # Use the custom resource outputs
        certificate_arn = certificate_creator.get_response_field("certificateArn")
        certificate_pem = certificate_creator.get_response_field("certificatePem")
        private_key = certificate_creator.get_response_field("keyPair.PrivateKey")

        # Create a role alias for KVS WebRTC
        kvs_webrtc_role_alias = iot.CfnRoleAlias(
            self,
            "KvsWebRtcRoleAlias",
            role_alias=KVS_IOT_ROLE_ALIAS,
            role_arn=kvs_webrtc_role.role_arn,
            credential_duration_seconds=3600,
        )

        # Create IoT policy for iot:Connect and iot:AssumeRoleWithCertificate
        kvs_webrtc_iot_role_alias_policy_document = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["iot:Connect", "iot:AssumeRoleWithCertificate"],
                    resources=[f"arn:aws:iot:{self.region}:{self.account}:rolealias/{KVS_IOT_ROLE_ALIAS}"],
                ),
            ]
        )

        kvs_webrtc_iot_role_alias_policy = iot.CfnPolicy(
            self,
            "IoTRoleAliasPolicy",
            policy_name=KVS_IOT_ROLE_ALIAS_POLICY,
            policy_document=kvs_webrtc_iot_role_alias_policy_document.to_json(),
        )

        # Attach the IoT policy to the certificate
        iot.CfnPolicyPrincipalAttachment(
            self,
            "IoTRoleAliasPolicyAttachment",
            policy_name=kvs_webrtc_iot_role_alias_policy.ref,
            principal=certificate_arn,
        )

        # Attach the certificate to the IoT thing
        iot.CfnThingPrincipalAttachment(
            self,
            "IoTThingPrincipalAttachment",
            thing_name=iot_thing.ref,
            principal=certificate_arn,
        )

        # Create a Kinesis Video Streams signaling channel
        kvs_signaling_channel = kvs.CfnSignalingChannel(
            self,
            "KvsSignalingChannel",
            name=SIGNAL_CHANNEL_NAME,
        )

        # Output the necessary information
        CfnOutput(self, "CertificateArn", value=certificate_arn)
        CfnOutput(self, "CertificatePem", value=certificate_pem)
        CfnOutput(self, "PrivateKey", value=private_key)
        CfnOutput(self, "ThingName", value=iot_thing.ref)
        CfnOutput(self, "RoleAlias", value=kvs_webrtc_role_alias.ref)
        CfnOutput(self, "SignalingChannelArn", value=kvs_signaling_channel.attr_arn)
        CfnOutput(self, "SignalingChannelName", value=kvs_signaling_channel.ref)

    @staticmethod
    def write_certificate_files(output_dir, certificate_pem, private_key):
        script_output_dir = os.path.join(os.getcwd(),output_dir)
        os.makedirs(script_output_dir, exist_ok=True)

        public_key_pem_file = os.path.join(script_output_dir, "device.cert.pem")
        with open(public_key_pem_file, "w", encoding="utf-8") as f:
            f.write(certificate_pem)

        private_key_pem_file = os.path.join(script_output_dir, "device.private.key")
        with open(private_key_pem_file, "w", encoding="utf-8") as f:
            f.write(private_key)

        print(f"Certificate files written to {script_output_dir}")