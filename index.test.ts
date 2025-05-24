import { handler } from './index';
import * as jwt from 'jsonwebtoken';

const fakeJwt = jwt.sign(
    { sub: '1234', scope: 'read' },
    'secret',
    {
        algorithm: 'HS256',
        header: { kid: 'abc123' },
        audience: 'test-aud',
        issuer: 'https://test-issuer/'
    } as jwt.SignOptions
);

jest.mock('jwks-rsa', () => {
    return {
        JwksClient: jest.fn().mockImplementation(() => ({
            getSigningKey: (kid: string, cb: Function) => {
                cb(null, {
                    getPublicKey: () => 'secret',
                });
            },
        })),
    };
});

describe('Lambda Authorizer', () => {
    it('returns allow policy for valid JWT', async () => {
        const event = {
            authorizationToken: `Bearer ${fakeJwt}`,
            methodArn: 'arn:aws:execute-api:test/method',
        };

        const response = await handler(event);

        expect(response.principalId).toBe('1234');
        expect(response.policyDocument.Statement[0].Effect).toBe('Allow');
        expect(response.context.scope).toBe('read');
    });

    it('returns deny policy for missing token', async () => {
        const event = {
            authorizationToken: '',
            methodArn: 'arn:aws:execute-api:test/method',
        };

        const response = await handler(event);

        expect(response.policyDocument.Statement[0].Effect).toBe('Deny');
    });

    it('returns deny policy for malformed token', async () => {
        const event = {
            authorizationToken: 'Bearer abc.def.ghi',
            methodArn: 'arn:aws:execute-api:test/method',
        };

        const response = await handler(event);

        expect(response.policyDocument.Statement[0].Effect).toBe('Deny');
    });
});
