import { APIGatewayAuthorizerResult } from 'aws-lambda';
import * as jwt from 'jsonwebtoken';
import { JwksClient } from 'jwks-rsa';
import * as util from 'util';

const jwtOptions = {
    audience: process.env.AUDIENCE,
    issuer: process.env.TOKEN_ISSUER,
};

const client = new JwksClient({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    jwksUri: process.env.JWKS_URI!,
});

const getSigningKey = util.promisify(client.getSigningKey.bind(client));

export const handler = async (event: any): Promise<APIGatewayAuthorizerResult> => {
    try {
        return await authorizeRequest(event);
    } catch (error) {
        console.error('Authorization error:', error);
        return denyAllPolicy();
    }
};

async function authorizeRequest(event: any): Promise<APIGatewayAuthorizerResult> {
    const token = extractBearerToken(event);
    const decodedHeader = jwt.decode(token, { complete: true });

    if (!decodedHeader || typeof decodedHeader !== 'object' || !decodedHeader.header?.kid) {
        throw new Error('Invalid token structure');
    }

    const key = await getSigningKey(decodedHeader.header.kid);
    const publicKey = key.getPublicKey();

    const decoded = jwt.verify(token, publicKey, jwtOptions) as any;

    return buildAllowPolicy(decoded.sub, event.methodArn, decoded.scope);
}

function extractBearerToken(event: any): string {
    const authToken = event?.authorizationToken ?? event?.headers?.Authorization;

    if (!authToken) {
        throw new Error('Authorization token is empty');
    }

    const match = authToken.match(/^Bearer (.+)$/);
    if (!match) {
        throw new Error(`Invalid Authorization token format - ${authToken}`);
    }

    return match[1];
}

function buildAllowPolicy(principalId: string, resource: string, scope: string): APIGatewayAuthorizerResult {
    return {
        principalId: principalId,
        policyDocument: {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: 'Allow',
                Resource: resource,
            }],
        },
        context: {
            scope: scope || '',
        },
    };
}

function denyAllPolicy(): APIGatewayAuthorizerResult {
    return {
        principalId: '*',
        policyDocument: {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: 'Deny',
                Resource: '*',
            }],
        },
    };
}
