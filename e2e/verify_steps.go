package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"

	util "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cucumber/godog"
	"github.com/stretchr/testify/assert"
)

func (issCtx *IssuerContext) verifyCertificateIssued(ctx context.Context) error {
	return issCtx.verifyCertificateState(ctx, "Ready", "True")
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

func (issCtx *IssuerContext) verifyCertificateUsage(ctx context.Context, usage string) error {
	cert := issCtx.parseCertificateSecret(ctx)

	var expectedX509Usages []x509.ExtKeyUsage
	for _, expectedUsage := range strings.Split(usage, ",") {
		mappedUsage, exists := usageMap[expectedUsage]
		if !exists {
			assert.FailNow(godog.T(ctx), "Expected usage %q not found in usageMap.", expectedUsage)
		}

		x509Usage, _ := util.ExtKeyUsageType(mappedUsage)
		expectedX509Usages = append(expectedX509Usages, x509Usage)
		if !slices.Contains(cert.ExtKeyUsage, x509Usage) {
			assert.FailNow(godog.T(ctx), fmt.Sprintf("Certificate usage mismatch. Found: %v, Expected: %v", cert.ExtKeyUsage, mappedUsage))
		}
	}

	if len(cert.ExtKeyUsage) != len(expectedX509Usages) {
		assert.FailNow(godog.T(ctx), fmt.Sprintf("Certificate has extra key usage types. Found: %v, Expected: %v", cert.ExtKeyUsage, expectedX509Usages))
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
