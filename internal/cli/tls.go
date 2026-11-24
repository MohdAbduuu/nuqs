// Address validation and pure-stdlib TLS certificate helpers for "nuqs serve".

package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"
)

const (
	selfSignedCertFile = "tls-cert.pem"
	selfSignedKeyFile  = "tls-key.pem"
)

// CheckServeAddr validates addr as host:port (or :port) and reports whether it
// binds strictly to a loopback address (127.0.0.0/8, ::1 or localhost).
func CheckServeAddr(addr string) (bool, error) {
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		p, perr := strconv.ParseUint(port, 10, 16)
		if perr != nil || p == 0 {
			err = errors.New("invalid port")
		}
	}
	if err != nil {
		return false, fmt.Errorf("--addr %q should look like 127.0.0.1:9002 or 0.0.0.0:9002", addr)
	}
	if host == "" {
		return false, nil
	}
	if host == "localhost" {
		return true, nil
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		return ip.IsLoopback(), nil
	}
	return false, nil
}

// EnsureSelfSignedCert returns paths to a persistent ECDSA P-256 self-signed
// TLS certificate and private key in dataDir, generating them when missing or
// expired. The certificate includes localhost, loopback and local LAN SANs.
func EnsureSelfSignedCert(dataDir, addr string) (string, string, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create TLS directory: %w", err)
	}
	certPath := filepath.Join(dataDir, selfSignedCertFile)
	keyPath := filepath.Join(dataDir, selfSignedKeyFile)
	if validExistingCert(certPath, keyPath, addr, time.Now()) {
		return certPath, keyPath, nil
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate TLS key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", fmt.Errorf("generate certificate serial: %w", err)
	}

	dnsNames, ips := collectSANs(addr)
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Nuqs Local Server", Organization: []string{"Nuqs"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("create self-signed certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("encode TLS key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("write TLS certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write TLS private key: %w", err)
	}
	return certPath, keyPath, nil
}

// BuildTLSConfig loads a PEM certificate pair and enforces TLS 1.2 or newer.
func BuildTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate/key: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, nil
}

// NetworkHintURL returns a reachable LAN URL when addr binds all interfaces
// (such as 0.0.0.0:9002 or :9002), or "" otherwise.
func NetworkHintURL(addr, scheme string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || (host != "" && host != "0.0.0.0" && host != "::") {
		return ""
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() && ip.IsPrivate() {
			return fmt.Sprintf("%s://%s:%s", scheme, ip.String(), port)
		}
	}
	return ""
}

// LocalAccessURL returns a clickable local browser URL for addr (replacing
// wildcard bind hosts like 0.0.0.0, :: or empty with 127.0.0.1).
func LocalAccessURL(addr, scheme string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return scheme + "://" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return fmt.Sprintf("%s://127.0.0.1:%s", scheme, port)
	}
	return fmt.Sprintf("%s://%s", scheme, addr)
}

func validExistingCert(certPath, keyPath, addr string, now time.Time) bool {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}
	// Refresh automatically if expired or expiring within 7 days.
	if !now.After(leaf.NotBefore) || !leaf.NotAfter.After(now.Add(7*24*time.Hour)) {
		return false
	}
	dnsNames, ips := collectSANs(addr)
	for _, name := range dnsNames {
		if leaf.VerifyHostname(name) != nil {
			return false
		}
	}
	for _, ip := range ips {
		if leaf.VerifyHostname(ip.String()) != nil {
			return false
		}
	}
	return true
}

func collectSANs(addr string) ([]string, []net.IP) {
	dnsNames := []string{"localhost"}
	if h, err := os.Hostname(); err == nil && h != "" && !slices.Contains(dnsNames, h) {
		dnsNames = append(dnsNames, h)
	}
	var ips []net.IP
	addIP := func(ip net.IP) {
		if ip == nil || ip.IsUnspecified() {
			return
		}
		for _, existing := range ips {
			if existing.Equal(ip) {
				return
			}
		}
		ips = append(ips, ip)
	}
	addIP(net.ParseIP("127.0.0.1"))
	addIP(net.ParseIP("::1"))
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
		if ip := net.ParseIP(host); ip != nil {
			addIP(ip)
		} else if !slices.Contains(dnsNames, host) {
			dnsNames = append(dnsNames, host)
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				addIP(ipnet.IP)
			}
		}
	}
	return dnsNames, ips
}
