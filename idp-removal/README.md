# iam-introspect
This is small lambda app to self check on an AWS Account for specific use-case. 

**How to Deploy**

run folowing command

*sh build.sh*

**How to Deploy**

1. Create SNS Topic for Email Notification (example name: idp-creation-notification)

2. Create IAM Role with Policy contains following permission (example policy: idp-removal-policy, role: idp-removal-role)

- Publish to SNS Topic

- List SAML Providers

- Delete SAML Provider

3. Deploy this application to Lambda and assign the IAM Role created from number 2

4. Configure Lambda Environment variable

- Set INTROSPECT_REGION with the region

- Set INTROSPECT_SNS_TOPIC with the SNS topic created from number 1

5. Create a EventBridge trigger by 1 minute interval
