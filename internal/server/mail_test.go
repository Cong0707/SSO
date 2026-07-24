package server

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSendSMTPMessageUsesImplicitTLS(t *testing.T) {
	certificate := newSMTPTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	messages := make(chan string, 1)
	serverErrors := make(chan error, 1)
	go serveSMTPTestConnection(tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}), messages, serverErrors)

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	err = sendSMTPMessage(smtpConnectionConfig{
		Host:        host,
		Port:        port,
		Username:    "sender@example.com",
		Password:    "secret",
		ImplicitTLS: true,
		TLSConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // Test server uses an ephemeral self-signed certificate.
		},
	}, "sender@example.com", []string{"receiver@example.com"}, []byte("Subject: test\r\n\r\nhello"))
	if err != nil {
		t.Fatalf("send SMTP message: %v", err)
	}

	select {
	case message := <-messages:
		if !strings.Contains(message, "Subject: test") || !strings.Contains(message, "hello") {
			t.Fatalf("unexpected SMTP message: %q", message)
		}
	case err := <-serverErrors:
		t.Fatalf("fake SMTP server failed: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SMTP message")
	}
}

func serveSMTPTestConnection(listener net.Listener, messages chan<- string, errors chan<- error) {
	connection, err := listener.Accept()
	if err != nil {
		errors <- err
		return
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	writeLine := func(line string) error {
		if _, err := writer.WriteString(line + "\r\n"); err != nil {
			return err
		}
		return writer.Flush()
	}
	if err := writeLine("220 localhost ESMTP"); err != nil {
		errors <- err
		return
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			errors <- err
			return
		}
		command := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(command, "EHLO"):
			if err := writeLine("250-localhost"); err != nil {
				errors <- err
				return
			}
			if err := writeLine("250 AUTH PLAIN"); err != nil {
				errors <- err
				return
			}
		case strings.HasPrefix(command, "AUTH PLAIN"):
			if err := writeLine("235 2.7.0 Authentication successful"); err != nil {
				errors <- err
				return
			}
		case strings.HasPrefix(command, "MAIL FROM:"):
			if err := writeLine("250 2.1.0 Sender OK"); err != nil {
				errors <- err
				return
			}
		case strings.HasPrefix(command, "RCPT TO:"):
			if err := writeLine("250 2.1.5 Recipient OK"); err != nil {
				errors <- err
				return
			}
		case command == "DATA":
			if err := writeLine("354 End data with <CR><LF>.<CR><LF>"); err != nil {
				errors <- err
				return
			}
			var message strings.Builder
			for {
				dataLine, err := reader.ReadString('\n')
				if err != nil {
					errors <- err
					return
				}
				if strings.TrimRight(dataLine, "\r\n") == "." {
					break
				}
				message.WriteString(dataLine)
			}
			messages <- message.String()
			if err := writeLine("250 2.0.0 Queued"); err != nil {
				errors <- err
				return
			}
		case command == "QUIT":
			_ = writeLine("221 2.0.0 Bye")
			return
		default:
			if err := writeLine("502 5.5.1 Command not implemented"); err != nil {
				errors <- err
				return
			}
		}
	}
}

func newSMTPTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate
}
