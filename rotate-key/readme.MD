# iam-introspect: rotate-key
This is small lambda app to rotate access key in parameter store

**How to Deploy**

run folowing command

    sh build.sh

**How to Deploy**

1. Create IAM Role with Policy contains following permission
   - ssm:GetParameter
   - ssm:PutParameter
   - iam:ListAccessKeys
   - iam:CreateAccessKey
   - iam:DeleteAccessKey
2. Deploy this application to Lambda and assign the IAM Role created from number 1
3. Configure Lambda Environment variable
   - Set ROTATE_KEY_REGION with the region
   - Set ROTATE_KEY_THRESHOLD with the rotation cycle periode in minute
   - Set ROTATE_KEY_APP_LIST with Parameter Store key
4. Create a EventBridge trigger by 1 day interval
