import { APIGatewayAuthorizerResult, Context } from 'aws-lambda';

export const handler = async (event: any, context: Context) => {
    const authHeader = event.headers.authorization;

    if (!authHeader) {
        return denyAllPolicy();
    }
}

function denyAllPolicy(): APIGatewayAuthorizerResult {
    return {
        "principalId": "*",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "*",
                    "Effect": "Deny",
                    "Resource": "*"
                }
            ]
        }
    }
}