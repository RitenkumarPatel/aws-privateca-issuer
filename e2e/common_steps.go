package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"log"

	"github.com/cert-manager/aws-privateca-issuer/pkg/api/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func getCaArn(caType string) string {
	caArn, exists := testContext.caArns[caType]

	if !exists {
		panic(fmt.Sprintf("Unknown CA Type: %s", caType))
	}

	return caArn
}

func getIssuerSpec(caType string) v1beta1.AWSPCAIssuerSpec {
	return v1beta1.AWSPCAIssuerSpec{
		Arn:    getCaArn(caType),
		Region: testContext.region,
	}
}

func (issCtx *IssuerContext) createNamespace(ctx context.Context) error {
	namespaceName := "pca-issuer-ns-" + uuid.New().String()
	namespace := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespaceName},
	}

	_, err := testContext.clientset.CoreV1().Namespaces().Create(ctx, &namespace, metav1.CreateOptions{})

	if err != nil {
		assert.FailNow(godog.T(ctx), "Failed to create namespace "+err.Error())
	}

	issCtx.namespace = namespaceName

	return nil
}

func (issCtx *IssuerContext) createSecret(ctx context.Context, accessKey string, secretKey string) error {
	secretName := "pca-issuer-secret-" + uuid.New().String()

	data := make(map[string][]byte)
	data[accessKey] = []byte(testContext.accessKey)
	data[secretKey] = []byte(testContext.secretKey)

	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName},
		Data:       data,
	}

	_, err := testContext.clientset.CoreV1().Secrets(issCtx.namespace).Create(ctx, &secret, metav1.CreateOptions{})

	if err != nil {
		assert.FailNow(godog.T(ctx), "Failed to create issuer secret "+err.Error())
	}

	awsSecretRef := v1beta1.AWSCredentialsSecretReference{
		SecretReference: v1.SecretReference{
			Name:      secretName,
			Namespace: issCtx.namespace,
		},
	}

	if accessKey != "AWS_ACCESS_KEY_ID" {
		awsSecretRef.AccessKeyIDSelector = v1.SecretKeySelector{
			Key: accessKey,
		}
	}

	if secretKey != "AWS_SECRET_ACCESS_KEY" {
		awsSecretRef.SecretAccessKeySelector = v1.SecretKeySelector{
			Key: secretKey,
		}
	}

	issCtx.secretRef = awsSecretRef
	return nil
}

func getBaseCertSpec(certType string, usages ...cmv1.KeyUsage) cmv1.CertificateSpec {
	sanitizedCertType := strings.Replace(strings.ToLower(certType), "_", "-", -1)

	log.Printf("Creating Certificate Spec for %s", usages)
	if len(usages) == 0 {
		usages = []cmv1.KeyUsage{cmv1.UsageAny}
	}

	certSpec := cmv1.CertificateSpec{
		Subject: &cmv1.X509Subject{
			Organizations: []string{"aws"},
		},
		DNSNames: []string{sanitizedCertType + "-cert.aws.com"},
		Duration: &metav1.Duration{
			Duration: 721 * time.Hour,
		},
		Usages: usages,
	}

	if certType == "RSA" {
		certSpec.PrivateKey = &cmv1.CertificatePrivateKey{
			Algorithm: cmv1.RSAKeyAlgorithm,
			Size:      2048,
		}
	}

	if certType == "ECDSA" {
		certSpec.PrivateKey = &cmv1.CertificatePrivateKey{
			Algorithm: cmv1.ECDSAKeyAlgorithm,
			Size:      256,
		}
	}

	return certSpec
}

func getCertSpec(certType string, usages ...cmv1.KeyUsage) cmv1.CertificateSpec {
	switch certType {
	case "RSA":
		return getBaseCertSpec(certType, usages...)
	case "ECDSA":
		return getBaseCertSpec(certType, usages...)
	case "SHORT_VALIDITY":
		return getCertSpecWithValidity(getBaseCertSpec("RSA"), 20, 5, usages...)
	case "CA":
		return getCaCertSpec(getBaseCertSpec("RSA"))
	default:
		panic(fmt.Sprintf("Unknown Certificate Type: %s", certType))
	}
}

func getCertSpecWithValidity(certSpec cmv1.CertificateSpec, duration time.Duration, renewBefore time.Duration, usages ...cmv1.KeyUsage) cmv1.CertificateSpec {
	certSpec.Duration = &metav1.Duration{
		Duration: duration * time.Hour,
	}
	certSpec.RenewBefore = &metav1.Duration{
		Duration: renewBefore * time.Hour,
	}
	// TODO: Check what happens if we input a usages with len 0, I think i check this elsewhere
	if len(usages) > 0 {
		certSpec.Usages = usages
	}

	return certSpec
}

func getCaCertSpec(certSpec cmv1.CertificateSpec) cmv1.CertificateSpec {
	certSpec.IsCA = true
	return getCertSpecWithValidity(certSpec, 20, 5)
}

func (issCtx *IssuerContext) issueCertificate(ctx context.Context, certType string) error {
	log.Printf("=== issueCertificate CALLED === certType: %s (NO USAGE SPECIFIED)", certType)
	return issCtx.issueCertificateInternal(ctx, certType)
}

func (issCtx *IssuerContext) issueCertificateInternal(ctx context.Context, certType string, usages ...cmv1.KeyUsage) error {
	sanitizedCertType := strings.Replace(strings.ToLower(certType), "_", "-", -1)
	issCtx.certName = issCtx.issuerName + "-" + sanitizedCertType + "-cert"
	certSpec := getCertSpec(certType, usages...)

	secretName := issCtx.certName + "-cert-secret"
	certSpec.SecretName = secretName
	certSpec.IssuerRef = cmmeta.ObjectReference{
		Kind:  issCtx.issuerType,
		Group: "awspca.cert-manager.io",
		Name:  issCtx.issuerName,
	}

	certificate := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: issCtx.certName},
		Spec:       certSpec,
	}

	_, err := testContext.cmClient.Certificates(issCtx.namespace).Create(ctx, &certificate, metav1.CreateOptions{})

	if err != nil {
		assert.FailNow(godog.T(ctx), "Could not create certificate: "+err.Error())
	}

	return nil
}

func (issCtx *IssuerContext) issueCertificateWithUsage(ctx context.Context, certType string, usageStr string) error {
	log.Printf("RECEIVED: %s", usageStr)
	usages := parseUsages(usageStr)
	log.Printf("Issuing certificate with usages: %v", usages)
	return issCtx.issueCertificateInternal(ctx, certType, usages...)
}

func parseUsages(usageStr string) []cmv1.KeyUsage {
	usageMap := map[string]cmv1.KeyUsage{
		"client_auth":       cmv1.UsageClientAuth,
		"server_auth":       cmv1.UsageServerAuth,
		"code_signing":      cmv1.UsageCodeSigning,
		"ocsp_signing":      cmv1.UsageOCSPSigning,
		"any":               cmv1.UsageAny,
	}

	parts := strings.Split(strings.ReplaceAll(usageStr, " ", ""), ",")
	var usages []cmv1.KeyUsage
	for _, part := range parts {
		if usage, exists := usageMap[strings.ToLower(part)]; exists {
			usages = append(usages, usage)
		}
	}

	log.Printf("Parsed usages: %v", usages)

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

func (issCtx *IssuerContext) verifyCertificateContent(ctx context.Context, usage string) error {
	// The secret name is typically the same as the certificate name + "-cert-secret"
	// or whatever was specified in the Certificate's spec.secretName
	secretName := issCtx.certName + "-cert-secret"

	certData, err := getCertificateData(ctx, testContext.clientset, issCtx.namespace, secretName)
	if err != nil {
		assert.FailNow(godog.T(ctx), "Failed to get certificate data: "+err.Error())
	}

	// Now you can perform additional validation on the certificate text
	// For example, check if it contains expected fields, is properly signed, etc.
	if len(certData) == 0 {
		assert.FailNow(godog.T(ctx), "Certificate data is empty")
	}

	log.Printf("Expected usage: %s", usage)
	log.Printf("Certificate Data: %s", certData)
	// You could add more specific validation here

	return nil
}
