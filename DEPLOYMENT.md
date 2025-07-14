# Railway Deployment Guide

## Prerequisites

1. A Railway account (https://railway.app)
2. Railway CLI installed (optional)
3. GitHub repository with the zkLogin Proving Service code

## Deployment Steps

### 1. Prepare the Repository

Ensure your repository includes:
- All source files (circuits, server.js, etc.)
- `Dockerfile` for building the container
- `railway.toml` configuration file
- `package.json` with dependencies

### 2. Deploy via Railway Dashboard

1. Log in to Railway Dashboard
2. Click "New Project" → "Deploy from GitHub repo"
3. Select your repository
4. Railway will automatically detect the Dockerfile
5. Wait for the build to complete (may take 5-10 minutes due to rapidsnark compilation)

### 3. Environment Variables (if needed)

Set the following in Railway's environment variables:
- `PORT` - Railway will provide this automatically
- Any other custom variables your service needs

### 4. Verify Deployment

Once deployed, Railway will provide a URL like:
```
https://your-service.railway.app
```

Test the endpoints:
```bash
# Health check
curl https://your-service.railway.app/health

# Service info
curl https://your-service.railway.app/

# Generate proof
curl -X POST https://your-service.railway.app/prove \
  -H "Content-Type: application/json" \
  -d '{
    "jwtHash": "14744269619966411208579211824598458697587494354926760081771325075741142829156",
    "nonce": "0",
    "pubKeyHash": "0"
  }'
```

## Important Notes

1. **Build Time**: The first deployment will take longer due to:
   - Installing build dependencies
   - Compiling rapidsnark from source
   - Building the Docker image

2. **Binary Compatibility**: The Dockerfile builds rapidsnark for Linux, ensuring compatibility with Railway's runtime environment.

3. **Resource Usage**: 
   - Proof generation is CPU-intensive
   - Consider Railway's resource limits for production use
   - Monitor usage and scale as needed

4. **Security**:
   - This is a demonstration implementation
   - For production, implement proper authentication
   - Consider rate limiting for the `/prove` endpoint

## Troubleshooting

1. **Build Failures**: Check Railway logs for compilation errors
2. **Runtime Errors**: Ensure all files are included in the Docker image
3. **Proof Generation Fails**: Verify circuit files and keys are properly copied

## Alternative Deployment

If you prefer to deploy a pre-built image:

1. Build locally:
```bash
docker build -t zklogin-prover .
```

2. Push to a registry (e.g., Docker Hub):
```bash
docker tag zklogin-prover yourusername/zklogin-prover
docker push yourusername/zklogin-prover
```

3. Deploy from Docker image in Railway 