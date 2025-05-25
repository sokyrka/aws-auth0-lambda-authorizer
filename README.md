# 🔐 AWS Lambda Authorizer with JWT + JWKS (Auth0-ready)
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Tested](https://img.shields.io/badge/tests-passing-blue)
![SAM](https://img.shields.io/badge/deploy-SAM--ready-orange)
![TypeScript](https://img.shields.io/badge/code-TypeScript-blue)

Custom AWS Lambda authorizer for API Gateway that validates JWTs using a JWKS endpoint.

---

## 📦 Tech Stack

- Node.js 22.x
- TypeScript + esbuild
- `jsonwebtoken`, `jwks-rsa`
- AWS Lambda + SAM
- Minimal `node_modules` for Lambda zip

---

## 🚀 Deployment Guide

### 1. 🛠 Install dependencies

```bash
npm install
```
### 2. ⚙️ Configure environment

Make sure the following values are available in your deployment:

- AUDIENCE — the JWT audience (e.g., API identifier)
- TOKEN_ISSUER — JWT issuer (e.g., https://your-tenant.auth0.com/)
- JWKS_URI — URL to JWKS endpoint (e.g., https://your-tenant.auth0.com/.well-known/jwks.json)

### 3. 📦 Build and package

```bash
npm run build
```

This will:

- Compile index.ts with esbuild to dist/index.js
- Create a minimal lambda-package/
- Zip the contents into aws-auth0-lambda-authorizer.zip (ready for deployment)

### 4. 🚀 Deploy with SAM

```bash
sam deploy --guided
```
When prompted, provide:

- Stack name
- AWS region
- AUDIENCE
- TOKEN_ISSUER
- JWKS_URI

## 🧪 Local Test

You can test the Lambda function locally using:
```bash
sam local invoke JwtAuthorizerFunction --event event.json
```

Example event.json:
```json
{
  "type": "TOKEN",
  "authorizationToken": "Bearer <your_jwt_token>",
  "methodArn": "arn:aws:execute-api:region:account-id:api-id/stage/GET/resource"
}
```

## ✅ Integration with API Gateway

1. Go to API Gateway → Authorizers
2. Add a new Lambda authorizer
3. Lambda Function: jwt-authorizer
4. Attach it to methods you want protected
5. Deployment stage must have permissions to call the Lambda

---

## 📎 Featured Portfolio Project

This Lambda Authorizer is featured in my professional portfolio on Upwork.  
🔗 View the project: [Upwork Portfolio](https://www.upwork.com/freelancers/~012f08ee1cb0554fb6?p=1926602258199896064)

If you're looking to build secure AWS-based APIs — feel free to reach out.