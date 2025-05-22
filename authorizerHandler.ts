import {APIGatewayAuthorizerResult} from 'aws-lambda';

export const handler = async (event: any) => {
    const authHeader = event.authorizationToken;

    if (!authHeader) {
        return denyAllPolicy();
    }
}


/**
 * Return an IAM policy that denies access to the API
 */
function denyAllPolicy(): APIGatewayAuthorizerResult {
    return {
        principalId: '*',
        policyDocument: {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: 'Allow',
                Resource: '*',
            }]
        }
    };
}