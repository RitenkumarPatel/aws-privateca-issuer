package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"

	util "github.com/cert-manager/cert-manager/pkg/api/util"
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

func (issCtx *IssuerContext) parseCertificateSecret(ctx context.Context) *x509.Certificate {
	secretName := issCtx.certName + "-cert-secret"

	certData, err := getCertificateData(ctx, testContext.clientset, issCtx.namespace, secretName)
	if err != nil {
		assert.FailNow(godog.T(ctx), "Failed to get certificate data: "+err.Error())
	}

	decodedData, _ := pem.Decode(certData)
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
	cert := issCtx.parseCertificateSecret(ctx)

	for _, expectedUsage := range strings.Split(usage, ",") {
		mappedUsage, exists := usageMap[expectedUsage]
		if !exists {
			assert.FailNow(godog.T(ctx), "Expected usage %q not found in usageMap.", expectedUsage)
		}

		x509Usage, _ := util.ExtKeyUsageType(mappedUsage)
		if !slices.Contains(cert.ExtKeyUsage, x509Usage) {
			assert.FailNow(godog.T(ctx), fmt.Sprintf("Certificate usage mismatch. Found: %v, Expected: %v", cert.ExtKeyUsage, mappedUsage))
		}
	}

	return nil
}

func (issCtx *IssuerContext) verifyCertificateAuthorityPathLen(ctx context.Context, pathLen int) error {
	cert := issCtx.parseCertificateSecret(ctx)

	if !cert.IsCA {
		assert.FailNow(godog.T(ctx), "Certificate is not a CA certificate")
	}
	if cert.MaxPathLen != pathLen {
		assert.FailNow(godog.T(ctx), fmt.Sprintf("Expected pathLen %d but got %d", pathLen, cert.MaxPathLen))
	}

	return nil
}
