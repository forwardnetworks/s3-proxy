package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type AWSCredentials struct {
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

var (
	credsMutex    sync.RWMutex
	currentCreds  AWSCredentials
	debug         = os.Getenv("DEBUG") == "1"
	ttlSeconds    = getEnvInt("TOKEN_TTL_SECONDS", 21600)
	region        = getEnv("AWS_REGION", "us-west-2")
	authAccessKey = os.Getenv("ACCESS_KEY_ID")
	authSecretKey = os.Getenv("SECRET_ACCESS_KEY")
	allowedCIDRs  []*net.IPNet
)

func getEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}

func getEnvInt(key string, fallback int) int {
	val := os.Getenv(key)
	if parsed, err := strconv.Atoi(val); err == nil {
		return parsed
	}
	return fallback
}

func logDebug(format string, a ...interface{}) {
	if debug {
		log.Printf(format, a...)
	}
}

func fetchIMDSToken(ttl int) (string, error) {
	req, _ := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", strconv.Itoa(ttl))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	token, _ := io.ReadAll(resp.Body)
	return string(token), nil
}

func fetchRole(token string) (string, error) {
	req, _ := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil)
	req.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	role, _ := io.ReadAll(resp.Body)
	return string(role), nil
}

func fetchCreds(token, role string) (AWSCredentials, error) {
	req, _ := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"+role, nil)
	req.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return AWSCredentials{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var creds AWSCredentials
	json.Unmarshal(body, &creds)
	return creds, nil
}

func refreshLoop() {
	for {
		logDebug("Refreshing credentials from IMDS")
		token, err := fetchIMDSToken(ttlSeconds)
		if err != nil {
			log.Printf("Token error: %v", err)
			time.Sleep(1 * time.Minute)
			continue
		}
		role, err := fetchRole(token)
		if err != nil {
			log.Printf("Role error: %v", err)
			time.Sleep(1 * time.Minute)
			continue
		}
		c, err := fetchCreds(token, role)
		if err != nil {
			log.Printf("Creds error: %v", err)
			time.Sleep(1 * time.Minute)
			continue
		}
		credsMutex.Lock()
		currentCreds = c
		credsMutex.Unlock()
		exp, _ := time.Parse(time.RFC3339, c.Expiration)
		sleep := time.Until(exp) - 5*time.Minute
		if sleep < 1*time.Minute {
			sleep = 1 * time.Minute
		}
		logDebug("Refreshed. Sleeping %v", sleep)
		time.Sleep(sleep)
	}
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			logDebug("Authorization header present — skipping custom auth")
			next.ServeHTTP(w, r)
			return
		}

		key := r.Header.Get("access_key")
		secret := r.Header.Get("secret_access_key")

		logDebug("Incoming headers: %+v", r.Header)
		logDebug("Incoming query: %s", r.URL.RawQuery)

		if key == "" || secret == "" {
			key = r.URL.Query().Get("access_key")
			secret = r.URL.Query().Get("secret_access_key")
		}
		if key != authAccessKey || secret != authSecretKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ipFilterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(allowedCIDRs) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		allowed := false
		for _, cidr := range allowedCIDRs {
			if cidr.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func s3ProxyHandler(w http.ResponseWriter, r *http.Request) {
	credsMutex.RLock()
	creds := currentCreds
	credsMutex.RUnlock()

	buf := &bytes.Buffer{}
	if r.Body != nil {
		io.Copy(buf, r.Body)
		r.Body.Close()
	}
	r.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))

	endpoint := fmt.Sprintf("https://s3.%s.amazonaws.com", region)
	url := endpoint + r.URL.Path + "?" + r.URL.RawQuery

	req, _ := http.NewRequest(r.Method, url, bytes.NewReader(buf.Bytes()))
	req.Header = r.Header.Clone()

	// Clear potentially conflicting headers
	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Date")
	req.Header.Del("X-Amz-Security-Token")
	req.Header.Del("X-Amz-Content-Sha256")
	req.Header.Del("X-Amz-User-Agent")
	for h := range req.Header {
		if strings.HasPrefix(strings.ToLower(h), "x-amz-") {
			req.Header.Del(h)
		}
	}
	logDebug("Cleared original AWS headers — re-signing request")

	signer := v4.NewSigner()
	awsCreds := aws.Credentials{
		AccessKeyID:     creds.AccessKeyId,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.Token,
		Source:          "shim",
	}
	sum := sha256.Sum256(buf.Bytes())
	payloadHash := hex.EncodeToString(sum[:])
	req.Header.Set("x-amz-content-sha256", payloadHash)
	err := signer.SignHTTP(context.Background(), awsCreds, req, payloadHash, "s3", region, time.Now())
	if err != nil {
		http.Error(w, "Signing error: "+err.Error(), 500)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Proxy error: "+err.Error(), 502)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func generateSelfSigned() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(mrand.Int63()),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" || authAccessKey == "" || authSecretKey == "" {
		log.Fatal("Missing required env: PORT, ACCESS_KEY_ID, SECRET_ACCESS_KEY")
	}

	// Parse ALLOWED_SOURCE_CIDRS env var
	cidrs := os.Getenv("ALLOWED_SOURCE_CIDRS")
	if cidrs != "" {
		for _, cidrStr := range strings.Split(cidrs, ",") {
			cidrStr = strings.TrimSpace(cidrStr)
			if cidrStr == "" {
				continue
			}
			_, cidr, err := net.ParseCIDR(cidrStr)
			if err != nil {
				log.Fatalf("Invalid CIDR in ALLOWED_SOURCE_CIDRS: %s", cidrStr)
			}
			allowedCIDRs = append(allowedCIDRs, cidr)
		}
	}

	go refreshLoop()

	cert, err := generateSelfSigned()
	if err != nil {
		log.Fatalf("TLS cert generation failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", ipFilterMiddleware(authMiddleware(http.HandlerFunc(s3ProxyHandler))))

	srv := &http.Server{
		Addr:      ":" + port,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}

	log.Printf("Listening on https://localhost:%s", port)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
