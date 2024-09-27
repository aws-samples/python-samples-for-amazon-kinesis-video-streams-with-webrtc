import argparse
import asyncio
import boto3
import json
import platform
import websockets
from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription, MediaStreamTrack
from aiortc.contrib.media import MediaPlayer, MediaRelay
from aiortc.sdp import candidate_from_sdp
from base64 import b64decode, b64encode
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.session import Session
import cv2
import threading
import queue
import os
import sys
import time
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


class VideoStreamHandler:
    def __init__(self):
        self.q = queue.Queue()
        self.con_flag = False
        self.end_flag = False

    def display_video(self):
        cv2.namedWindow("Video", cv2.WINDOW_NORMAL)
        cv2.resizeWindow("Video", 600, 400)
        cv2.moveWindow("Video", 0, 0)

        while not self.end_flag:
            if not self.q.empty():
                img_view = self.q.get()
                logging.debug("Displaying frame")
                cv2.imshow("Video", img_view)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                self.end_flag = True
        cv2.destroyAllWindows()


class SimpleVideoTrack(MediaStreamTrack):
    kind = "video"

    def __init__(self, track, video_handler):
        super().__init__()
        self.track = track
        self.video_handler = video_handler
        self.frame_count = 0
        self.last_frame_time = time.time()
        print("SimpleVideoTrack initialized")

    async def recv(self):
        try:
            frame = await asyncio.wait_for(self.track.recv(), timeout=5.0)
            # frame count for debugging
            self.frame_count += 1
            current_time = time.time()
            fps = 1 / (current_time - self.last_frame_time) if self.frame_count > 1 else 0
            self.last_frame_time = current_time            
            logging.debug(f"Simple: Received frame {self.frame_count} (FPS: {fps:.2f})")

            img = frame.to_ndarray(format="bgr24")
            logging.debug("Adding frame to queue")
            self.video_handler.q.put(img)
            return frame
        except asyncio.TimeoutError:
            logging.error("Timeout waiting for video frame")
            return None
        except Exception as e:
            logging.error(f"Error receiving video frame: {e}")
            return None


class MediaTrackManager:
    def __init__(self, file_path=None):
        self.file_path = file_path

    def create_media_track(self):
        relay = MediaRelay()
        options = {'framerate': '30', 'video_size': '1280x720'}
        system = platform.system()

        if self.file_path and not os.path.exists(self.file_path):
            raise FileNotFoundError(f"The file {self.file_path} does not exist.")

        if system == 'Darwin':
            media = MediaPlayer('default:default', format='avfoundation', options=options) if not self.file_path else MediaPlayer(self.file_path)
        elif system == 'Windows':
            media = MediaPlayer('video=Integrated Camera', format='dshow', options=options)
        elif system == 'Linux':
            media = MediaPlayer('/dev/video0', format='v4l2', options=options) if not self.file_path else MediaPlayer(self.file_path)
        else:
            raise NotImplementedError(f"Unsupported platform: {system}")

        audio_track = relay.subscribe(media.audio) if media.audio else None
        video_track = relay.subscribe(media.video) if media.video else None

        if audio_track is None and video_track is None:
            raise ValueError("Neither audio nor video track could be created from the source.")
        return audio_track, video_track


class KinesisVideoClient:
    def __init__(self, client_id, region, channel_arn, credentials, video_handler, file_path=None):
        self.client_id = client_id
        self.region = region
        self.channel_arn = channel_arn
        self.credentials = credentials
        self.media_manager = MediaTrackManager(file_path)
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
        self.video_handler = video_handler
        self.pc = None

    def get_signaling_channel_endpoint(self): 
        if self.endpoints is None:  # Check if endpoints are already fetched
            endpoints = self.kinesisvideo.get_signaling_channel_endpoint(
                ChannelARN=self.channel_arn,
                SingleMasterChannelEndpointConfiguration={'Protocols': ['HTTPS', 'WSS'], 'Role': 'VIEWER'}
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
            ClientId=self.client_id
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
            params={'X-Amz-ChannelARN': self.channel_arn, 'X-Amz-ClientId': self.client_id},
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
            'messagePayload': b64encode(json.dumps(payload).encode('ascii')).decode('ascii'),
            'recipientClientId': client_id,
        })

    async def handle_sdp_offer(self, audio_track, video_track, websocket):
        iceServers = self.prepare_ice_servers()
        configuration = RTCConfiguration(iceServers=iceServers)
        self.pc = RTCPeerConnection(configuration=configuration)

        @self.pc.on('connectionstatechange')
        async def on_connectionstatechange():
            logging.info(f'[{self.client_id}] connectionState: {self.pc.connectionState}')
            self.video_handler.con_flag = self.pc.connectionState == "connected"

        @self.pc.on('iceconnectionstatechange')
        async def on_iceconnectionstatechange():
            logging.info(f'[{self.client_id}] ICE connectionState: {self.pc.iceConnectionState}')

        @self.pc.on('icegatheringstatechange')
        async def on_icegatheringstatechange():
            logging.info(f'[{self.client_id}] ICE gatheringState: {self.pc.iceGatheringState}')

        @self.pc.on('track')
        def on_track(track):
            logging.info(f"Received track: {track.kind}")
            if track.kind == "video":
                # when a new video track is received from the remote peer, 
                # an instance of SimpleVideoTrack is created by passing the received track object to its constructor.
                # This instance ( local_video ) is then added to the peer connection using pc.addTrack(local_video).
                local_video = SimpleVideoTrack(track, self.video_handler)
                self.pc.addTrack(local_video)

        @self.pc.on('icecandidate')
        async def on_icecandidate(event):
            if event.candidate:
                logging.info(f"Local ICE candidate: {event.candidate}")
                await websocket.send(self.encode_msg('ICE_CANDIDATE', {
                    'candidate': event.candidate.candidate,
                    'sdpMid': event.candidate.sdpMid,
                    'sdpMLineIndex': event.candidate.sdpMLineIndex,
                }, self.client_id))

        # By adding the SimpleVideoTrack last, you ensure that it's ready to handle incoming video after the local tracks are set up.
        # Sets up the outgoing media first (audio and video tracks from the viewer to the master).
        if audio_track:
            self.pc.addTrack(audio_track)
        if video_track:
            self.pc.addTrack(video_track)
        #  Prepares for incoming video by adding the SimpleVideoTrack.
        self.pc.addTrack(SimpleVideoTrack)

        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)
        
        await websocket.send(self.encode_msg('SDP_OFFER', {'sdp': self.pc.localDescription.sdp, 'type': self.pc.localDescription.type}, self.client_id))

    async def handle_ice_candidate(self, payload):
        candidate = candidate_from_sdp(payload['candidate'])
        candidate.sdpMid = payload['sdpMid']
        candidate.sdpMLineIndex = payload['sdpMLineIndex']
        logging.info(f"Adding remote ICE candidate: {candidate}")
        await self.pc.addIceCandidate(candidate)

    async def signaling_client(self):
        audio_track, video_track = self.media_manager.create_media_track()
        self.get_signaling_channel_endpoint()
        wss_url = self.create_wss_url()
        try:
            async with websockets.connect(wss_url) as websocket:
                logging.info('Signaling Server Connected!')
                await self.handle_sdp_offer(audio_track, video_track, websocket)
                await self.handle_messages(websocket)
        except Exception as e:
            logging.error(f"Exception: {e}")
        finally:
            self.video_handler.con_flag = False
            if self.pc and self.pc.connectionState != "closed":
                await self.pc.close()

    async def handle_messages(self, websocket):
        async for message in websocket:
            msg_type, payload, _ = self.decode_msg(message)
            if msg_type == 'SDP_ANSWER':
                logging.info(f"Received SDP answer: {payload}")
                await self.pc.setRemoteDescription(RTCSessionDescription(sdp=payload["sdp"], type=payload["type"]))
            elif msg_type == 'ICE_CANDIDATE':
                try:
                    await self.handle_ice_candidate(payload)
                except Exception as e:
                    logging.error(f"Error adding ICE candidate: {e}")

        while True:
            await asyncio.sleep(1)
            if self.pc.iceConnectionState == "failed":
                logging.error("ICE connection failed")
                break
            if hasattr(self.pc, '_senders'):
                for sender in self.pc._senders:
                    if isinstance(sender._track, SimpleVideoTrack):
                        if time.time() - sender._track.last_frame_time > 5:
                            logging.warning("No video frames received in the last 5 seconds")


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
        

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--channel-arn', type=str, required=True, help='the ARN of the signaling channel')
    parser.add_argument('--file-path', type=str, help='the path to the video file to play (optional)')
    parser.add_argument('--use-device-certs', action='store_true', help='Use system certificates')
    args = parser.parse_args()

    if not AWS_DEFAULT_REGION:
        raise Exception("AWS_DEFAULT_REGION environment variable should be configured.\ni.e. export AWS_DEFAULT_REGION=us-west-2")

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

    video_handler = VideoStreamHandler()

    # Start the WebRTC connection in a separate thread
    webrtc_thread = threading.Thread(target=lambda: asyncio.run(
        KinesisVideoClient(
            client_id="VIEWER", 
            region=AWS_DEFAULT_REGION, 
            channel_arn=args.channel_arn, 
            credentials=credentials,
            video_handler=video_handler, 
            file_path=args.file_path
        ).signaling_client()))
    webrtc_thread.start()

    # Run the video display in the main thread
    video_handler.display_video()

    webrtc_thread.join()

if __name__ == '__main__':
    main()
