package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cert-manager/aws-privateca-issuer/pkg/api/v1beta1"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CertificateConfig struct {
	CertType string
	Usages   []cmv1.KeyUsage
}

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

func getBaseCertSpec(certConfig CertificateConfig) cmv1.CertificateSpec {
	sanitizedCertType := strings.Replace(strings.ToLower(certConfig.CertType), "_", "-", -1)

	if len(certConfig.Usages) == 0 {
		certConfig.Usages = []cmv1.KeyUsage{cmv1.UsageDigitalSignature, cmv1.UsageKeyEncipherment} // These are cert-manager's defaults
	}

	certSpec := cmv1.CertificateSpec{
		Subject: &cmv1.X509Subject{
			Organizations: []string{"aws"},
		},
		DNSNames: []string{sanitizedCertType + "-cert.aws.com"},
		Duration: &metav1.Duration{
			Duration: 721 * time.Hour,
		},
		Usages: certConfig.Usages,
	}

	if certConfig.CertType == "RSA" {
		certSpec.PrivateKey = &cmv1.CertificatePrivateKey{
			Algorithm: cmv1.RSAKeyAlgorithm,
			Size:      2048,
		}
	}

	if certConfig.CertType == "ECDSA" {
		certSpec.PrivateKey = &cmv1.CertificatePrivateKey{
			Algorithm: cmv1.ECDSAKeyAlgorithm,
			Size:      256,
		}
	}

	return certSpec
}

func getCertSpec(certConfig CertificateConfig) cmv1.CertificateSpec {
	switch certConfig.CertType {
	case "RSA":
		return getBaseCertSpec(certConfig)
	case "ECDSA":
		return getBaseCertSpec(certConfig)
	case "SHORT_VALIDITY":
		return getCertSpecWithValidity(getBaseCertSpec(certConfig), 20, 5)
	case "CA":
		return getCaCertSpec(getBaseCertSpec(certConfig))
	default:
		panic(fmt.Sprintf("Unknown Certificate Type: %s", certConfig.CertType))
	}
}

func getCertSpecWithValidity(certSpec cmv1.CertificateSpec, duration time.Duration, renewBefore time.Duration) cmv1.CertificateSpec {
	certSpec.Duration = &metav1.Duration{
		Duration: duration * time.Hour,
	}
	certSpec.RenewBefore = &metav1.Duration{
		Duration: renewBefore * time.Hour,
	}

	return certSpec
}

func getCaCertSpec(certSpec cmv1.CertificateSpec) cmv1.CertificateSpec {
	certSpec.IsCA = true
	return getCertSpecWithValidity(certSpec, 20, 5)
}

func (issCtx *IssuerContext) issueCertificateWithKeyType(ctx context.Context, certType string) error {
	certConfig := CertificateConfig{
		CertType: certType,
		Usages:   nil,
	}
	return issCtx.issueCertificate(ctx, certConfig)
}

func (issCtx *IssuerContext) issueCertificateWithUsage(ctx context.Context, certType string, usageStr string) error {
	usages := parseUsages(usageStr)
	certConfig := CertificateConfig{
		CertType: certType,
		Usages:   usages,
	}
	return issCtx.issueCertificate(ctx, certConfig)
}

func (issCtx *IssuerContext) issueCertificate(ctx context.Context, certConfig CertificateConfig) error {
	sanitizedCertType := strings.Replace(strings.ToLower(certConfig.CertType), "_", "-", -1)
	issCtx.certName = issCtx.issuerName + "-" + sanitizedCertType + "-cert"
	certSpec := getCertSpec(certConfig)

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
