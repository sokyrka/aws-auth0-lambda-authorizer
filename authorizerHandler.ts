import {APIGatewayAuthorizerResult} from 'aws-lambda';
import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa'
import * as util from 'util'

export const handler = async (event: any) => {
    const authToken = event?.authorizationToken ?? event?.headers?.Authorization;

    if (!authToken) {
        console.log('Authorization token is empty')
        return denyAllPolicy();
    }

    const match = authToken.match(/^Bearer (.*)$/)

    if (!match || match.length < 2) {
        console.log(`Invalid Authorization token - ${authToken} does not match "Bearer .*"`)
        return denyAllPolicy();
    }

    const token = match[1];

    const decoded = jwt.decode(token, {complete: true});
    if (!decoded || !decoded.header || !decoded.header.kid) {
        console.log('Invalid token')
        return denyAllPolicy();
    }

    const getSigningKey = util.promisify(client.getSigningKey);
    return getSigningKey(decoded.header.kid)
        .then((key) => {
            const signingKey = key.getPublicKey;
            return jwt.verify(token, signingKey, jwtOptions);
        })
        .then((decoded) => ({
            principalId: decoded.sub,
            policyDocument: allowPolicy(event.methodArn),
            context: {scope: decoded.scope}
        }));
}

const jwtOptions = {
    audience: process.env.AUDIENCE,
    issuer: process.env.TOKEN_ISSUER
};

const client = jwksClient({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    jwksUri: process.env.JWKS_URI
});

/**
 * Return an IAM policy that allows access to the API
 */
function allowPolicy(resource): APIGatewayAuthorizerResult {
    return {
        principalId: 'apigateway.amazonaws.com',
        policyDocument: {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: 'Allow',
                Resource: resource,
            }]
        }
    };
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
                Effect: 'Deny',
                Resource: '*',
            }]
        }
    };
}