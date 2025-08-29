# s3proxy

A lightweight, S3-compatible proxy server that allows legacy applications using IAM user credentials to interact with AWS S3 via an EC2 instance profile.  
This is especially useful in environments where direct use of access/secret keys is prohibited.

---

## 🔧 Features

- ✅ S3-compatible API: `GET`, `PUT`, `HEAD`, `DELETE`, `LIST`
- ✅ Automatic region detection via `HeadBucket`
- ✅ All AWS SigV4 requests are re-signed with the instance profile credentials, including support for AWS header normalization
- ✅ Source IP restriction and static credential validation for added access control
- ✅ Support for `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (chunked uploads from AWS SDKs)
- ✅ Minimal dependencies, ships as a single binary
- ✅ Easy to deploy behind a private IP or load balancer
- ✅ Supports deployment as a `systemd` service

---

## 🚀 Usage

### Quick Start

```bash
AWS_REGION=us-west-2 PORT=8080 ./s3proxy
```

The proxy will bind to `0.0.0.0:8080` (or the port you provide) and expose an S3-compatible API surface.

In your app or tool that supports S3-compatible storage, configure:

| Setting            | Value                      |
|--------------------|----------------------------|
| Service endpoint   | `http://<proxy-ip>:8080`   |
| Access key ID      | `test` (placeholder)       |
| Secret access key  | `test` (placeholder)       |
| Bucket             | Any existing S3 bucket     |
| SSL Validation     | **Disabled**               |

> ⚠️ Auth credentials are ignored — the proxy always uses the EC2 instance profile attached to the instance it runs on.

### Recommended: `systemd` Setup

Create a systemd unit file (e.g., `/etc/systemd/system/s3proxy.service`):

```ini
[Unit]
Description=S3 Proxy
After=network.target

[Service]
Type=simple
Environment="AWS_REGION=us-west-2"
Environment="PORT=8080"
# Optionally restrict by source IP CIDR or static credentials:
# Environment="ALLOWED_SOURCE_CIDRS=10.0.0.0/8,192.168.1.0/24"
# Environment="ACCESS_KEY_ID=test"
# Environment="SECRET_ACCESS_KEY=test"
ExecStart=/usr/local/bin/s3proxy
Restart=on-failure
User=s3proxy

[Install]
WantedBy=multi-user.target
```

Then reload systemd and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now s3proxy
```

---

## 🧪 Tested With

- AWS SDK for Java (`aws-sdk-java`)
- Backup appliances with S3-compatible output
- Veeam (immutable mode off)
- MinIO clients (mc)
- Custom `curl` uploads

---

## 📦 Build from Source

```bash
go mod tidy
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o s3proxy main.go
```

---

## ⚙️ Environment Variables

- `AWS_REGION`: Optional. Fallback/default region to use for S3 operations.
- `PORT`: Optional. Port to serve HTTP on (default: `9000`).
- `ACCESS_KEY_ID`: Optional. If set, only requests signed with this access key are accepted (static credential validation).
- `SECRET_ACCESS_KEY`: Optional. If set, only requests signed with this secret key are accepted.
- `ALLOWED_SOURCE_CIDRS`: Optional. Comma-separated list of allowed source IPv4 CIDRs (e.g. `10.0.0.0/8,192.168.1.0/24`). Requests from other IPs are rejected.
- `DEBUG`: Optional. Set to `1` to enable verbose debug logging.

---

## 🛡️ Security

- All incoming AWS SigV4 requests are re-signed with the instance profile credentials, ensuring requests are always authorized with short-lived credentials.
- Supports source IP restriction via `ALLOWED_SOURCE_CIDRS` to limit access to trusted networks.
- Supports basic static credential validation (`ACCESS_KEY_ID` / `SECRET_ACCESS_KEY`) for additional access control.
- Intended for use in controlled environments behind a firewall or as part of a private integration workflow.

---

## 🧰 Future Improvements

- Support for `POST` (multipart upload init)
- Signed URL passthrough
- `x-amz-meta-*` headers preservation
- Optional TLS support

---

## License

MIT
