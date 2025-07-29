# s3proxy

A lightweight, S3-compatible proxy server that allows legacy applications using IAM user credentials to interact with AWS S3 via an EC2 instance profile.  
This is especially useful in environments where direct use of access/secret keys is prohibited.

---

## 🔧 Features

- ✅ S3-compatible API: `GET`, `PUT`, `HEAD`, `DELETE`, `LIST`
- ✅ Automatic region detection via `HeadBucket`
- ✅ Transparent credential use via instance profile
- ✅ Support for `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (chunked uploads from AWS SDKs)
- ✅ Minimal dependencies, ships as a single binary
- ✅ Easy to deploy behind a private IP or load balancer

---

## 🚀 Usage

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

---

## 🛡️ Security

This proxy does not verify `Authorization` headers. It is intended for use in controlled environments behind a firewall or as part of a private integration workflow.

---

## 🧰 Future Improvements

- Support for `POST` (multipart upload init)
- Signed URL passthrough
- `x-amz-meta-*` headers preservation
- Optional TLS support

---

## License

MIT
