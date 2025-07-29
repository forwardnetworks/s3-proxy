package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var (
	defaultRegion string
	baseCfg       aws.Config
	clientCache   = make(map[string]*s3.Client)
	cacheLock     sync.Mutex
	allowedCIDRs  []*net.IPNet
)

func loadTLSConfig() (*tls.Config, error) {
	certPath := os.Getenv("TLS_CERT_PATH")
	keyPath := os.Getenv("TLS_KEY_PATH")

	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS cert and key: %v", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}

	log.Printf("[WARN] TLS_CERT_PATH or TLS_KEY_PATH not set, generating self-signed certificate")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Self-Signed"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	certPem := &bytes.Buffer{}
	keyPem := &bytes.Buffer{}

	if err := pem.Encode(certPem, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, fmt.Errorf("failed to encode cert pem: %v", err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, fmt.Errorf("failed to encode key pem: %v", err)
	}

	cert, err := tls.X509KeyPair(certPem.Bytes(), keyPem.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %v", err)
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func startServer(port string) {
	tlsConfig, err := loadTLSConfig()
	if err != nil {
		log.Fatalf("Failed to load TLS config: %v", err)
	}

	server := &http.Server{
		Addr:      ":" + port,
		Handler:   http.DefaultServeMux,
		TLSConfig: tlsConfig,
	}

	if debugEnabled {
		log.Printf("S3 proxy server running on :%s with TLS\n", port)
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}

var debugEnabled bool

func main() {
	debugEnabled = os.Getenv("DEBUG") == "1"

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatalf("PORT environment variable must be set")
	}

	if strings.ToLower(os.Getenv("DEBUG")) == "true" {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	if debugEnabled {
		log.Printf("Default AWS region: %s", defaultRegion)
	}

	defaultRegion = os.Getenv("AWS_REGION")

	if cidrList := os.Getenv("ALLOWED_CIDRS"); cidrList != "" {
		for _, cidr := range strings.Split(cidrList, ",") {
			_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
			if err != nil {
				log.Fatalf("Invalid CIDR in ALLOWED_CIDRS: %v", err)
			}
			allowedCIDRs = append(allowedCIDRs, network)
		}
	}

	var err error
	baseCfg, err = config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Unable to load base AWS config: %v", err)
	}

	http.HandleFunc("/", s3Handler)
	startServer(port)
}

func s3Handler(w http.ResponseWriter, r *http.Request) {
	if len(allowedCIDRs) > 0 {
		ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Printf("Failed to parse RemoteAddr: %v", err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		ip := net.ParseIP(ipStr)
		allowed := false
		for _, cidr := range allowedCIDRs {
			if cidr.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Printf("Request from %s denied by CIDR policy", ip)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	if debugEnabled {
		log.Printf("[REQUEST] %s %s", r.Method, r.URL.Path)
		log.Printf("[HEADERS] %+v", r.Header)
	}

	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "Bucket not specified", http.StatusBadRequest)
		return
	}
	bucket := parts[0]

	switch r.Method {
	case "GET":
		if len(parts) == 1 || parts[1] == "" {
			handleListBucket(w, bucket)
		} else {
			handleDownload(w, bucket, parts[1])
		}
	case "PUT":
		if len(parts) < 2 {
			http.Error(w, "Key not specified", http.StatusBadRequest)
			return
		}
		handleUpload(w, r, bucket, parts[1])
	case "DELETE":
		if len(parts) < 2 {
			http.Error(w, "Key not specified", http.StatusBadRequest)
			return
		}
		handleDelete(w, bucket, parts[1])
	case "HEAD":
		if len(parts) < 2 || parts[1] == "" {
			http.Error(w, "Object key must be specified", http.StatusBadRequest)
			return
		}
		handleHead(w, r, bucket, parts[1])
	default:
		http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
	}
}

func getS3ClientForBucket(bucket string) (*s3.Client, error) {
	cacheLock.Lock()
	defer cacheLock.Unlock()

	if client, ok := clientCache[bucket]; ok {
		return client, nil
	}

	region := defaultRegion
	if region == "" {
		if debugEnabled {
			log.Printf("[INFO] Resolving region for bucket: %s", bucket)
		}
		r, err := manager.GetBucketRegion(context.TODO(), s3.NewFromConfig(baseCfg), bucket)
		if err != nil {
			return nil, fmt.Errorf("could not determine region for bucket %s: %v", bucket, err)
		}
		region = r
		if debugEnabled {
			log.Printf("[INFO] Detected region %s for bucket %s", region, bucket)
		}
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load config for region %s: %v", region, err)
	}

	client := s3.NewFromConfig(cfg)
	clientCache[bucket] = client
	return client, nil
}

func handleListBucket(w http.ResponseWriter, bucket string) {
	if debugEnabled {
		log.Printf("[LIST] Bucket: %s", bucket)
	}
	client, err := getS3ClientForBucket(bucket)
	if err != nil {
		if debugEnabled {
			log.Printf("[ERROR] %v", err)
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		if debugEnabled {
			log.Printf("[ERROR] list bucket: %v", err)
		}
		http.Error(w, "Failed to list bucket: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprintln(w, `<?xml version="1.0" encoding="UTF-8"?>`)
	fmt.Fprintln(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	for _, obj := range resp.Contents {
		fmt.Fprintf(w, "  <Contents><Key>%s</Key></Contents>\n", *obj.Key)
	}
	fmt.Fprintln(w, `</ListBucketResult>`)
}

func handleDownload(w http.ResponseWriter, bucket, key string) {
	if key == "" {
		if debugEnabled {
			log.Printf("[ERROR] key missing for download: bucket=%s", bucket)
		}
		http.Error(w, "Object key must be specified", http.StatusBadRequest)
		return
	}
	if debugEnabled {
		log.Printf("[DOWNLOAD] Bucket: %s, Key: %s", bucket, key)
	}
	client, err := getS3ClientForBucket(bucket)
	if err != nil {
		if debugEnabled {
			log.Printf("[ERROR] %v", err)
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if debugEnabled {
			log.Printf("[ERROR] download: %v", err)
		}
		http.Error(w, "Failed to download object: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func handleUpload(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if key == "" {
		if debugEnabled {
			log.Printf("[ERROR] key missing for upload: bucket=%s", bucket)
		}
		http.Error(w, "Object key must be specified", http.StatusMethodNotAllowed)
		return
	}
	if debugEnabled {
		log.Printf("[UPLOAD] Bucket: %s, Key: %s", bucket, key)
	}
	client, err := getS3ClientForBucket(bucket)
	if err != nil {
		if debugEnabled {
			log.Printf("[ERROR] %v", err)
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var body io.ReadCloser
	if r.Header.Get("X-Amz-Content-Sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		if debugEnabled {
			log.Printf("[UPLOAD] Detected streaming AWS chunked payload")
		}

		var fullPayload bytes.Buffer
		reader := bufio.NewReader(r.Body)

		for {
			// Read chunk size line
			line, err := reader.ReadString('\n')
			if err != nil {
				if debugEnabled {
					log.Printf("[ERROR] reading chunk header: %v", err)
				}
				http.Error(w, "Invalid chunked payload", http.StatusBadRequest)
				return
			}

			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Parse chunk size
			chunkSizeStr := strings.Split(line, ";")[0]
			chunkSize, err := strconv.ParseInt(chunkSizeStr, 16, 64)
			if err != nil {
				if debugEnabled {
					log.Printf("[ERROR] invalid chunk size: %s", chunkSizeStr)
				}
				http.Error(w, "Invalid chunk size", http.StatusBadRequest)
				return
			}
			if chunkSize == 0 {
				break
			}

			// Read chunk data
			chunk := make([]byte, chunkSize)
			_, err = io.ReadFull(reader, chunk)
			if err != nil {
				if debugEnabled {
					log.Printf("[ERROR] reading chunk data: %v", err)
				}
				http.Error(w, "Failed to read chunk", http.StatusBadRequest)
				return
			}

			fullPayload.Write(chunk)

			// Read trailing \r\n
			_, err = reader.ReadString('\n')
			if err != nil {
				if debugEnabled {
					log.Printf("[ERROR] reading chunk trailer: %v", err)
				}
				http.Error(w, "Invalid chunk trailer", http.StatusBadRequest)
				return
			}
		}

		body = io.NopCloser(bytes.NewReader(fullPayload.Bytes()))
	} else {
		body = r.Body
	}

	input := &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   body,
	}

	_, err = client.PutObject(context.TODO(), input)
	if err != nil {
		if debugEnabled {
			log.Printf("[ERROR] upload: %v", err)
		}
		http.Error(w, "Failed to upload: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Uploaded %s/%s\n", bucket, key)
}

func handleDelete(w http.ResponseWriter, bucket, key string) {
	if debugEnabled {
		log.Printf("[DELETE] Bucket: %s, Key: %s", bucket, key)
	}
	client, err := getS3ClientForBucket(bucket)
	if err != nil {
		if debugEnabled {
			log.Printf("[ERROR] %v", err)
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if debugEnabled {
			log.Printf("[ERROR] delete: %v", err)
		}
		http.Error(w, "Failed to delete: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Deleted %s/%s\n", bucket, key)
}

func handleHead(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if debugEnabled {
		log.Printf("[HEAD] Bucket: %s, Key: %s", bucket, key)
	}
	client, err := getS3ClientForBucket(bucket)
	if err != nil {
		if debugEnabled {
			log.Printf("[ERROR] %v", err)
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if debugEnabled {
			log.Printf("[ERROR] head object: %v", err)
		}
		http.Error(w, "Failed to HEAD object: "+err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}
