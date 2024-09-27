
# Welcome to your CDK Python project!

You should explore the contents of this project. It demonstrates a CDK app with an instance of a stack (`infra_stack`)
which contains an Amazon SQS queue that is subscribed to an Amazon SNS topic.

The `cdk.json` file tells the CDK Toolkit how to execute your app.

This project is set up like a standard Python project.  The initialization process also creates
a virtualenv within this project, stored under the .venv directory.  To create the virtualenv
it assumes that there is a `python3` executable in your path with access to the `venv` package.
If for any reason the automatic creation of the virtualenv fails, you can create the virtualenv
manually once the init process completes.

## when you run as a separate module (optional)
> [!NOTE]
> This is necessary only when you are running this CDK separately from the main project.

To manually create a virtualenv on MacOS and Linux:

```
python3 -m venv .venv
```

After the init process completes and the virtualenv is created, you can use the following
step to activate your virtualenv.

```
source .venv/bin/activate
```

If you are a Windows platform, you would activate the virtualenv like this:

```
.venv\Scripts\activate.bat
```

Once the virtualenv is activated, you can install the required dependencies.

```
pip install -r requirements.txt
```

## Deploy

You can now synthesize the CloudFormation template for this code.

```
cdk synth
```

This provisions the necessary AWS resources for the project, such as IoT Core resources like things, certificates, policies, role alias, IAM role, and IAM policy for Amazon KVS.

```
cdk deploy
```

Run wrtie_certs.py to download IoT device Certificates to the script-output folder.

```
python script/write_certs.py
```
