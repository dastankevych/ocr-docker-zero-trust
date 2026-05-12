# Deploying OCR Zero Trust Enclave to AWS

This repository has been modified to act as a **canonical enclave workload** similar to `ztinfra-enclaveproducedhtml`.
The Python OCR script runs alongside the Rust attestation server (which acts as a local proxy over `vsock`).

## Steps to Deploy

### 1. Build the Docker Image

Build the Docker container locally:
```bash
docker build -t ocr-nitro-enclave:latest .
```

### 2. Build the Nitro Enclave Image (EIF)

Use the AWS Nitro CLI to convert the Docker image into an `.eif` file and extract PCR measurements:
```bash
nitro-cli build-enclave 
  --docker-uri ocr-nitro-enclave:latest 
  --output-file ocr-nitro-enclave.eif > measurements.json
```
*Note: Make sure your EC2 instance or local environment supports `nitro-cli`.*

### 3. Generate `provenance.json`

Create a `provenance.json` file combining your PCR measurements with release metadata. This file is required by the `ztbrowser` parent proxy and the AWS CLI scripts.
```json
{
  "service": "ocr-zero-trust",
  "release_id": "v1.0.0",
  "workload_id": "ocr-nitro-enclave",
  "repo_url": "https://github.com/your-username/ocr-docker-zero-trust",
  "oci_image_digest": "sha256:...",
  "pcr0": "00000... (from measurements.json)",
  "pcr1": "00000... (from measurements.json)",
  "pcr2": "00000... (from measurements.json)"
}
```

### 4. Deploy using `scripts/aws-cli`

From the `ztbrowser-mono` repository, run the `full-deploy.sh` script passing the `provenance.json` and `.eif` file.
*(You will need your AWS credentials configured and proper IAM roles set up for EC2/Nitro).*

```bash
cd /path/to/ztbrowser-mono
export PROVENANCE_PATH=/path/to/ocr-docker-zero-trust/provenance.json
export EIF_PATH=/path/to/ocr-docker-zero-trust/ocr-nitro-enclave.eif
./scripts/aws-cli/full-deploy.sh
```

### 5. Start the Parent Proxy

If `full-deploy.sh` does not automatically start the parent proxy, or if you are running it manually:
```bash
export PROVENANCE_PATH=/path/to/ocr-docker-zero-trust/provenance.json
export MEASUREMENTS_PATH=/path/to/ocr-docker-zero-trust/measurements.json
./scripts/aws-run-parent-proxy.sh
```

### 6. Validate with Site-kit

Finally, use the site-kit extension or the `ztbrowser-site-kit` CLI to validate the live AWS endpoint.

```bash
npx ztbrowser-site-kit validate https://<your-ec2-ip-or-domain>
```

**Known limits (Упор в ключ):**
If you hit issues with keys or SSL certs during deploy, make sure you've bootstrapped the demo PKI in `ztbrowser-mono/demo-service-repo/demo-pki/` or updated `aws-deploy/` to provide the appropriate domain certificates for the proxy.
