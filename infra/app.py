#!/usr/bin/env python3

import aws_cdk as cdk

from kvswebrtc.kvswebrtc_stack import KvsWebRtcStack


app = cdk.App()
KvsWebRtcStack(app, "KvsWebRtcStack")

app.synth()
