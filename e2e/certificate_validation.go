package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"crypto/x509"
	"encoding/pem"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cucumber/godog"
	"github.com/stretchr/testify/assert"
)

var usageMap = map[string]cmv1.KeyUsage{
	"client_auth":       cmv1.UsageClientAuth,
	"server_auth":       cmv1.UsageServerAuth,
	"digital_signature": cmv1.UsageDigitalSignature,
	"code_signing":      cmv1.UsageCodeSigning,
	"ocsp_signing":      cmv1.UsageOCSPSigning,
	"any":               cmv1.UsageAny,
}

func parseUsages(usageStr string) []cmv1.KeyUsage {
	parts := strings.Split(usageStr, ",")
	var usages []cmv1.KeyUsage
	for _, part := range parts {
		if usage, exists := usageMap[strings.ToLower(part)]; exists {
			usages = append(usages, usage)
		} else {
			assert.FailNow(godog.T(context.Background()), "Unknown usage: "+part)
		}
	}

	return usages
}

func (issCtx *IssuerContext) verifyCertificateIssued(ctx context.Context) error {
	return issCtx.verifyCertificateState(ctx, "Ready", "True")
}

func (issCtx *IssuerContext) verifyCertificateState(ctx context.Context, reason string, status string) error {
	err := waitForCertificateState(ctx, testContext.cmClient, issCtx.certName, issCtx.namespace, reason, status)

	if err != nil {
		assert.FailNow(godog.T(ctx), "Certificate did not reach specified state, Reason = "+reason+", Status = "+status+": "+err.Error())
	}

	return nil
}

func (issCtx *IssuerContext) verifyCertificateRequestState(ctx context.Context, reason string, status string) error {
	certificateRequestName := fmt.Sprintf("%s-%d", issCtx.certName, 1)
	waitForCertificateRequestToBeCreated(ctx, testContext.cmClient, certificateRequestName, issCtx.namespace)
	err := waitForCertificateRequestState(ctx, testContext.cmClient, certificateRequestName, issCtx.namespace, reason, status)

	if err != nil {
		assert.FailNow(godog.T(ctx), "Certificate Request did not reach specified state, Condition = "+reason+", Status = "+status+": "+err.Error())
	}

	return nil
}

func (issCtx *IssuerContext) getCertificateSecret(ctx context.Context) *x509.Certificate {
	// The secret name is typically the same as the certificate name + "-cert-secret"
	secretName := issCtx.certName + "-cert-secret"

	certData, err := getCertificateData(ctx, testContext.clientset, issCtx.namespace, secretName)
	if err != nil {
		assert.FailNow(godog.T(ctx), "Failed to get certificate data: "+err.Error())
	}

	decodedData, _ := pem.Decode([]byte(certData))
	if decodedData == nil {
		assert.FailNow(godog.T(ctx), "Failed to decode certificate data")
	}

	cert, err := x509.ParseCertificate(decodedData.Bytes)
	if err != nil {
		assert.FailNow(godog.T(ctx), "Failed to parse certificate: "+err.Error())
	}
	return cert
}

func (issCtx *IssuerContext) verifyCertificateUsage(ctx context.Context, usage string) error {
	cert := issCtx.getCertificateSecret(ctx)

	usageLabels := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageClientAuth:  "client_auth",
		x509.ExtKeyUsageServerAuth:  "server_auth",
		x509.ExtKeyUsageCodeSigning: "code_signing",
		x509.ExtKeyUsageOCSPSigning: "ocsp_signing",
		x509.ExtKeyUsageAny:         "any",
	}

	expectedUsages := strings.Split(usage, ",")

	// Check if all expected usages are present in the certificate
	for _, expectedUsage := range expectedUsages {
		found := false
		for _, extUsage := range cert.ExtKeyUsage {
			if label, exists := usageLabels[extUsage]; exists {
				if label == expectedUsage {
					log.Printf("Found expected usage type in certificate: %s\n", label)
					found = true
					break
				}
			}
		}
		if !found {
			assert.FailNow(godog.T(ctx), "Certificate did not have expected usage: "+expectedUsage)
		}
	}

	return nil
}

func (issCtx *IssuerContext) verifyCertificateAuthority(ctx context.Context, pathLen string) error {
	cert := issCtx.getCertificateSecret(ctx)

	if !cert.IsCA {
		assert.FailNow(godog.T(ctx), "Certificate is not a CA certificate")
	}

	expectedPathLen := -1
	// Parse expected pathLen
	if pathLen != "unlimited" {
		expectedPathLen = 0
		for _, char := range pathLen {
			if char >= '0' && char <= '9' {
				expectedPathLen = expectedPathLen*10 + int(char-'0')
			}
		}
	}

	// Verify pathLen constraint
	if expectedPathLen == -1 {
		if cert.MaxPathLen != -1 {
			assert.FailNow(godog.T(ctx), fmt.Sprintf("Expected unlimited pathLen but got %d", cert.MaxPathLen))
		}
	} else {
		if cert.MaxPathLen != expectedPathLen {
			assert.FailNow(godog.T(ctx), fmt.Sprintf("Expected pathLen %d but got %d", expectedPathLen, cert.MaxPathLen))
		}
	}

	return nil
}
