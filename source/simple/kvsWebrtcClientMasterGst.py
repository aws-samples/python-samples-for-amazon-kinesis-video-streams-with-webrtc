import argparse
import asyncio
import json 
import numpy as np 
import boto3 
import websockets
from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription, MediaStreamTrack
from aiortc.contrib.media import MediaBlackhole
from aiortc.sdp import candidate_from_sdp
from av import VideoFrame, AudioFrame
from base64 import b64decode, b64encode
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.session import Session
from fractions import Fraction
import gi 
gi.require_version('Gst', '1.0')
gi.require_version('GstVideo', '1.0')
from gi.repository import Gst, GstVideo, GLib
import os
import sys
import logging
import requests
from typing import Dict, Optional
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, stream=sys.stdout)

# Construct script_output_path
script_output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../infra/script-output')

load_dotenv(dotenv_path=f"{script_output_path}/.env")  # take environment variables from .env.
IOT_CREDENTIAL_PROVIDER = os.getenv('IOT_CREDENTIAL_PROVIDER')
THING_NAME = os.getenv('THING_NAME')
ROLE_ALIAS = os.getenv('ROLE_ALIAS')
CERT_FILE = f"{script_output_path}/{os.getenv('CERT_FILE')}"
KEY_FILE = f"{script_output_path}/{os.getenv('KEY_FILE')}"
ROOT_CA = f"{script_output_path}/{os.getenv('ROOT_CA')}"
AWS_DEFAULT_REGION = os.getenv('AWS_DEFAULT_REGION')

# Converts list of plugins to gst-launch string
def to_gst_string(elements):
    return " ! ".join(elements)

def get_num_channels(video_format):
    """Get the number of channels for a given GstVideo.VideoFormat."""
    if video_format == GstVideo.VideoFormat.RGB:
        return 3
    elif video_format == GstVideo.VideoFormat.RGBA:
        return 4
    elif video_format == GstVideo.VideoFormat.GRAY8:
        return 1
    else:
        raise ValueError(f"Unsupported video format: {video_format}")

def get_np_dtype(video_format):
    """Get the numpy dtype for a given GstVideo.VideoFormat."""
    if video_format in [GstVideo.VideoFormat.RGB, GstVideo.VideoFormat.RGBA, GstVideo.VideoFormat.GRAY8]:
        return np.uint8
    else:
        raise ValueError(f"Unsupported video format: {video_format}")


class GstreamerPipeline: 
    def __init__(self, pipeline_str): 
        Gst.init(None) 
        try:
            self.pipeline = Gst.parse_launch(pipeline_str)
            # Start playing
            ret = self.pipeline.set_state(Gst.State.PLAYING)
            if ret == Gst.StateChangeReturn.FAILURE:
                print(f"Verify the GStreamer pipeline by running: gst-launch-1.0 {pipeline_str}")
                raise Exception("Unable to set the pipeline to the playing state")
        except GLib.Error as e:
            print(f"GStreamer error: {e}")
            return
        except Exception as e:
            print(f"Error: {e}")
            return

        self.video_sink = self.pipeline.get_by_name('appsink-video') 
        self.audio_sink = self.pipeline.get_by_name('appsink-audio') 
        self.video_track = None 
        self.audio_track = None 
        
        if not (self.video_sink or self.audio_sink):
            raise ValueError("Pipeline must contain at least one appsink named 'appsink-video' or 'appsink-audio'")

        if self.video_sink:
            print("setting video_track")
            self.video_track = GstreamerAppSink('video', self.video_sink)

        if self.audio_sink:
            print("setting audio_track")
            self.audio_sink = GstreamerAppSink('audio', self.audio_sink)

    def cleanup(self):
        # Stop the pipeline
        self.pipeline.set_state(Gst.State.NULL)


class GstreamerAppSink(MediaStreamTrack):
    def __init__(self, kind, appsink):
        super().__init__()
        self.kind = kind
        self.appsink = appsink

    async def recv(self):
        sample = self.appsink.emit('pull-sample')
        if sample is None:
            print("No video sample available")
            return Gst.FlowReturn.ERROR

        buffer = sample.get_buffer()
        caps = sample.get_caps()
        success, map_info = buffer.map(Gst.MapFlags.READ)
        if not success:
            raise RuntimeError("Could not map buffer data")

        try:
            if self.kind == "video":
                structure = caps.get_structure(0)
                width = structure.get_int("width").value
                height = structure.get_int("height").value
                video_format = GstVideo.VideoFormat.from_string(structure.get_value('format'))
                num_channels = get_num_channels(video_format)
                dtype = get_np_dtype(video_format)
                array = np.ndarray((height, width, num_channels), buffer=map_info.data, dtype=dtype)
                frame = VideoFrame.from_ndarray(array, format="rgb24")
                frame.pts = int(buffer.pts / Gst.MSECOND)
                frame.time_base = Fraction(1, 1000)
                return frame
            elif self.kind == "audio":
                structure = caps.get_structure(0)
                rate = structure.get_int("rate").value
                array = np.frombuffer(map_info.data, dtype=np.int16)
                frame = AudioFrame.from_ndarray(array, format="s16", layout="mono")
                frame.sample_rate = rate
                frame.pts = int(buffer.pts / Gst.MSECOND)
                frame.time_base = Fraction(1, 1000)
                return frame
        finally:
            buffer.unmap(map_info)


class KinesisVideoClient:
    def __init__(self, pipeline_str, region, channel_arn, credentials):
        self.region = region
        self.channel_arn = channel_arn
        self.credentials = credentials
        self.media_manager = GstreamerPipeline(pipeline_str)
        self.video_track = self.media_manager.video_track
        self.audio_track = self.media_manager.audio_track
        if self.credentials:
            self.kinesisvideo = boto3.client('kinesisvideo', 
                                             region_name=self.region, 
                                             aws_access_key_id=self.credentials['accessKeyId'],
                                             aws_secret_access_key=self.credentials['secretAccessKey'],
                                             aws_session_token=self.credentials['sessionToken']
                                            )
        else:
            self.kinesisvideo = boto3.client('kinesisvideo', region_name=self.region)
        self.endpoints = None
        self.endpoint_https = None
        self.endpoint_wss = None
        self.ice_servers = None 
        self.PCMap = {}
        self.DCMap = {}

    def get_signaling_channel_endpoint(self):
        if self.endpoints is None:  # Check if endpoints are already fetched
            endpoints = self.kinesisvideo.get_signaling_channel_endpoint(
                ChannelARN=self.channel_arn,
                SingleMasterChannelEndpointConfiguration={'Protocols': ['HTTPS', 'WSS'], 'Role': 'MASTER'}
            )
            self.endpoints = {
                'HTTPS': next(o['ResourceEndpoint'] for o in endpoints['ResourceEndpointList'] if o['Protocol'] == 'HTTPS'),
                'WSS': next(o['ResourceEndpoint'] for o in endpoints['ResourceEndpointList'] if o['Protocol'] == 'WSS')
            }
            self.endpoint_https = self.endpoints['HTTPS']
            self.endpoint_wss = self.endpoints['WSS']
        return self.endpoints            

    def prepare_ice_servers(self):
        if self.credentials:
            kinesis_video_signaling = boto3.client('kinesis-video-signaling',
                                                   endpoint_url=self.endpoint_https,
                                                   region_name=self.region,
                                                   aws_access_key_id=self.credentials['accessKeyId'],
                                                   aws_secret_access_key=self.credentials['secretAccessKey'],
                                                   aws_session_token=self.credentials['sessionToken']
                                                 )
        else:
            kinesis_video_signaling = boto3.client('kinesis-video-signaling',
                                                endpoint_url=self.endpoint_https,
                                                region_name=self.region)
        ice_server_config = kinesis_video_signaling.get_ice_server_config(
            ChannelARN=self.channel_arn,
            ClientId='MASTER'
        )

        iceServers = [RTCIceServer(urls=f'stun:stun.kinesisvideo.{self.region}.amazonaws.com:443')]
        for iceServer in ice_server_config['IceServerList']:
            iceServers.append(RTCIceServer(
                urls=iceServer['Uris'],
                username=iceServer['Username'],
                credential=iceServer['Password']
            ))
        self.ice_servers = iceServers

        return self.ice_servers

    def create_wss_url(self):
        if self.credentials:
            auth_credentials = Credentials(
                access_key=self.credentials['accessKeyId'],
                secret_key=self.credentials['secretAccessKey'],
                token=self.credentials['sessionToken']
            )
        else:
            session = Session()
            auth_credentials = session.get_credentials()

        SigV4 = SigV4QueryAuth(auth_credentials, 'kinesisvideo', self.region, 299)
        aws_request = AWSRequest(
            method='GET',
            url=self.endpoint_wss,
            params={'X-Amz-ChannelARN': self.channel_arn, 'X-Amz-ClientId': 'MASTER'}
        )
        SigV4.add_auth(aws_request)
        PreparedRequest = aws_request.prepare()
        return PreparedRequest.url

    def decode_msg(self, msg):
        try:
            data = json.loads(msg)
            payload = json.loads(b64decode(data['messagePayload'].encode('ascii')).decode('ascii'))
            return data['messageType'], payload, data.get('senderClientId')
        except json.decoder.JSONDecodeError:
            return '', {}, ''

    def encode_msg(self, action, payload, client_id):
        return json.dumps({
            'action': action,
            'messagePayload': b64encode(json.dumps(payload.__dict__).encode('ascii')).decode('ascii'),
            'recipientClientId': client_id,
        })

    async def handle_sdp_offer(self, payload, client_id, audio_track, video_track, websocket):
        iceServers = self.prepare_ice_servers()
        configuration = RTCConfiguration(iceServers=iceServers)
        pc = RTCPeerConnection(configuration=configuration)
        self.DCMap[client_id] = pc.createDataChannel('kvsDataChannel')
        self.PCMap[client_id] = pc

        @pc.on('connectionstatechange')
        async def on_connectionstatechange():
            if client_id in self.PCMap:
                print(f'[{client_id}] connectionState: {self.PCMap[client_id].connectionState}')

        @pc.on('iceconnectionstatechange')
        async def on_iceconnectionstatechange():
            if client_id in self.PCMap:
                print(f'[{client_id}] iceConnectionState: {self.PCMap[client_id].iceConnectionState}')

        @pc.on('icegatheringstatechange')
        async def on_icegatheringstatechange():
            if client_id in self.PCMap:
                print(f'[{client_id}] iceGatheringState: {self.PCMap[client_id].iceGatheringState}')

        @pc.on('signalingstatechange')
        async def on_signalingstatechange():
            if client_id in self.PCMap:
                print(f'[{client_id}] signalingState: {self.PCMap[client_id].signalingState}')

        @pc.on('track')
        def on_track(track):
            MediaBlackhole().addTrack(track)

        @pc.on('datachannel')
        async def on_datachannel(channel):
            @channel.on('message')
            def on_message(dc_message):
                for i in self.PCMap:
                    if self.DCMap[i].readyState == 'open':
                        try:
                            self.DCMap[i].send(f'broadcast: {dc_message}')
                        except Exception as e:
                            print(f"Error sending message: {e}")
                    else:
                         print(f"Data channel {i} is not open. Current state: {self.DCMap[i].readyState}")
                print(f'[{channel.label}] datachannel_message: {dc_message}')

        if audio_track:
            print(f'[handle_sdp_offer] Adding audio track: {audio_track.kind}')
            self.PCMap[client_id].addTrack(audio_track)
        if video_track:
            print(f'[handle_sdp_offer] Adding video track: {video_track.kind}')
            self.PCMap[client_id].addTrack(video_track)
            
        await self.PCMap[client_id].setRemoteDescription(RTCSessionDescription(
            sdp=payload['sdp'],
            type=payload['type']
        ))
        await self.PCMap[client_id].setLocalDescription(await self.PCMap[client_id].createAnswer())
        await websocket.send(self.encode_msg('SDP_ANSWER', self.PCMap[client_id].localDescription, client_id))

    async def handle_ice_candidate(self, payload, client_id):
        if client_id in self.PCMap:
            candidate = candidate_from_sdp(payload['candidate'])
            candidate.sdpMid = payload['sdpMid']
            candidate.sdpMLineIndex = payload['sdpMLineIndex']
            print(f"Adding ICE candidate for client {client_id}: {candidate}")
            await self.PCMap[client_id].addIceCandidate(candidate)

    async def signaling_client(self):
        self.get_signaling_channel_endpoint() 
        wss_url = self.create_wss_url()

        while True:
            try:
                async with websockets.connect(wss_url) as websocket:
                    print('Signaling Server Connected!')
                    async for message in websocket:
                        msg_type, payload, client_id = self.decode_msg(message)
                        if msg_type == 'SDP_OFFER':
                            await self.handle_sdp_offer(payload, client_id, self.audio_track, self.video_track, websocket)
                        elif msg_type == 'ICE_CANDIDATE':
                            await self.handle_ice_candidate(payload, client_id)
            except websockets.ConnectionClosed:
                print('Connection closed, reconnecting...')
                wss_url = self.create_wss_url()
                continue


class IoTCredentialProvider:
    def __init__(self, endpoint: str, region: str, thing_name: str, role_alias: str, 
                 cert_path: str, key_path: str, root_ca_path: str):
        self.endpoint = endpoint
        self.region = region
        self.thing_name = thing_name
        self.role_alias = role_alias
        self.cert_path = cert_path
        self.key_path = key_path
        self.root_ca_path = root_ca_path

    def get_temporary_credentials(self) -> Optional[Dict[str, str]]:
        url = f"https://{self.endpoint}/role-aliases/{self.role_alias}/credentials"
        headers = {'x-amzn-iot-thingname': self.thing_name}

        try:
            response = requests.get(
                url,
                headers=headers,
                cert=(self.cert_path, self.key_path),
                verify=self.root_ca_path,
                timeout=(10, 20)  # 10 seconds for connecting, 20 seconds for reading
            )

            if response.status_code == 200:
                credentials = response.json()['credentials']
                print("Temporary credentials obtained successfully.")
                return credentials
            else:
                print(f"Failed to obtain credentials. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return None
        

async def run_client(client):
    try:
        await client.signaling_client()
    finally:
        client.media_manager.cleanup()
        # Gather all tasks except the current one
        pending_tasks = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
        await asyncio.gather(*pending_tasks, return_exceptions=True)

async def main():
    DEFAULT_PIPELINE = to_gst_string([
        "filesrc location=./_assets/sample.mp4",
        "qtdemux",
        "h264parse",
        "avdec_h264",
        "videoconvert",
        "videoscale",
        "video/x-raw,format=RGB",
        "queue",
        "appsink name=appsink-video emit-signals=True"
    ])

    parser = argparse.ArgumentParser(description='Kinesis Video Streams WebRTC Client')
    parser.add_argument("--pipeline", default=DEFAULT_PIPELINE, help="Gstreamer pipeline without gst-launch")
    parser.add_argument('--channel-arn', type=str, required=True, help='the ARN of the signaling channel')
    parser.add_argument('--use-device-certs', action='store_true', help='Use system certificates')
    args = parser.parse_args()

    if not AWS_DEFAULT_REGION:
        raise Exception("AWS_DEFAULT_REGION environment variable should be configured.\ni.e. export AWS_DEFAULT_REGION=us-west-2")

    try:
        if args.use_device_certs:
            provider = IoTCredentialProvider(
                endpoint=IOT_CREDENTIAL_PROVIDER,
                region=AWS_DEFAULT_REGION,
                thing_name=THING_NAME,
                role_alias=ROLE_ALIAS,
                cert_path=CERT_FILE,
                key_path=KEY_FILE,
                root_ca_path=ROOT_CA
            )
            credentials = provider.get_temporary_credentials()
            if not credentials:
                raise Exception("Failed to obtain temporary credentials")
        else:
            credentials = None

        client = KinesisVideoClient(
            pipeline_str=args.pipeline,
            region=AWS_DEFAULT_REGION,
            channel_arn=args.channel_arn,
            credentials=credentials
        )

        await run_client(client)
    except Exception as e:
        print(f"Error: {e}")
        return

if __name__ == "__main__": 
    asyncio.run(main())