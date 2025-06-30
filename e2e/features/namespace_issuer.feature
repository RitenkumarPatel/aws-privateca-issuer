@AWSPCAIssuer
Feature: Issue certificates using an AWSPCAIssuer 
  As a user of the aws-privateca-issuer
  I need to be able to issue certificates using an AWSPCAIssuer so I can scope down permissions to a single namespace

  Background: Create unique namespace
    Given I create a namespace	

  Scenario Outline: Issue a certificate
    Given I create an AWSPCAIssuer using a <caType> CA
    When I issue a <certType> certificate
    Then the certificate should be issued successfully

    Examples:
      | caType | certType       |
      | RSA    | SHORT_VALIDITY |
      | RSA    | RSA            |
      | RSA    | ECDSA          |
      | RSA    | CA             |
      | ECDSA  | SHORT_VALIDITY |
      | ECDSA  | RSA            |
      | ECDSA  | ECDSA          |
      | ECDSA  | CA             |

  @KubernetesSecrets
  Scenario Outline: Issue a certificate using a secret for AWS credentials
    Given I create a Secret with keys <accessKeyId> and <secretKeyId> for my AWS credentials
    And I create an AWSPCAIssuer using a <caType> CA
    When I issue a <certType> certificate
    Then the certificate should be issued successfully

    Examples:
      | accessKeyId       | secretKeyId           | caType | certType       |
      | AWS_ACCESS_KEY_ID | AWS_SECRET_ACCESS_KEY | RSA    | SHORT_VALIDITY |
      | AWS_ACCESS_KEY_ID | AWS_SECRET_ACCESS_KEY | RSA    | RSA            |
      | AWS_ACCESS_KEY_ID | AWS_SECRET_ACCESS_KEY | RSA    | ECDSA          |
      | AWS_ACCESS_KEY_ID | AWS_SECRET_ACCESS_KEY | RSA    | CA             |
      | AWS_ACCESS_KEY_ID | AWS_SECRET_ACCESS_KEY | ECDSA  | SHORT_VALIDITY |
      | AWS_ACCESS_KEY_ID | AWS_SECRET_ACCESS_KEY | ECDSA  | RSA            |
      | AWS_ACCESS_KEY_ID | AWS_SECRET_ACCESS_KEY | ECDSA  | ECDSA          |
      | AWS_ACCESS_KEY_ID | AWS_SECRET_ACCESS_KEY | ECDSA  | CA             |

    @KeySelectors
    Examples:
      | accessKeyId       | secretKeyId           | caType | certType       |
      | myKeyId           | mySecret              | RSA    | SHORT_VALIDITY |
      | myKeyId           | mySecret              | RSA    | RSA            |
      | myKeyId           | mySecret              | RSA    | ECDSA          |
      | myKeyId           | mySecret              | RSA    | CA             |
      | myKeyId           | mySecret              | ECDSA  | SHORT_VALIDITY |
      | myKeyId           | mySecret              | ECDSA  | RSA            |
      | myKeyId           | mySecret              | ECDSA  | ECDSA          |
      | myKeyId           | mySecret              | ECDSA  | CA             |

    @KeyUsage
      Scenario Outline: Issue certificate with specific usage
        Given I create an AWSPCAIssuer using a <caType> CA
        When I issue a <certType> certificate with usage <usage>
        Then the certificate should be issued successfully
        And the certificate should be issued with usage <usage>

        Examples:
          | caType | certType | usage                    |
          | RSA    | RSA      | client_auth              |
          | RSA    | RSA      | server_auth              |
          | RSA    | RSA      | code_signing             |
          | RSA    | RSA      | ocsp_signing             |
          | RSA    | RSA      | any                      |
          | RSA    | RSA      | client_auth,server_auth  |
    
    @TemplatingIssuer
      Scenario Outline: Issue certificate with specific template
      Given I create an AWSPCAIssuer with template <templateArn> using a <caType> CA
      When I issue a <certType> certificate with usage <usage>
      Then the certificate should be issued successfully
      And the certificate should be issued with usage <expectedUsage>

      Examples:
        | caType | certType | templateArn                                                | usage                   | expectedUsage             |
        | ECDSA  | RSA      | EndEntityCertificate/V1                                    | client_auth,server_auth | client_auth,server_auth   |
        | ECDSA  | RSA      | EndEntityClientAuthCertificate/V1                          | client_auth             | client_auth               |
        | ECDSA  | RSA      | EndEntityServerAuthCertificate/V1                          | server_auth             | server_auth               |
        | ECDSA  | RSA      | CodeSigningCertificate/V1                                  | code_signing            | code_signing              |
        | ECDSA  | RSA      | OCSPSigningCertificate/V1                                  | ocsp_signing            | ocsp_signing              |

        | ECDSA  | ECDSA    | EndEntityCertificate_APIPassthrough/V1                     | any                     | client_auth,server_auth   |
        | ECDSA  | ECDSA    | EndEntityClientAuthCertificate_APIPassthrough/V1           | any                     | client_auth               |
        | ECDSA  | ECDSA    | EndEntityServerAuthCertificate_APIPassthrough/V1           | any                     | server_auth               |
        | ECDSA  | ECDSA    | CodeSigningCertificate_APIPassthrough/V1                   | any                     | code_signing              |
        | ECDSA  | ECDSA    | OCSPSigningCertificate_APIPassthrough/V1                   | any                     | ocsp_signing              |

        | RSA    | RSA      | EndEntityCertificate_CSRPassthrough/V1                     | ocsp_signing            | client_auth,server_auth   |
        | RSA    | RSA      | EndEntityClientAuthCertificate_CSRPassthrough/V1           | client_auth,server_auth | client_auth               |
        | RSA    | RSA      | EndEntityServerAuthCertificate_CSRPassthrough/V1           | client_auth             | server_auth               |
        | RSA    | RSA      | CodeSigningCertificate_CSRPassthrough/V1                   | server_auth             | code_signing              |
        | RSA    | RSA      | OCSPSigningCertificate_CSRPassthrough/V1                   | code_signing            | ocsp_signing              |


    @PositiveCATests
      Scenario Outline: Issue certificate with specific template
      Given I create an AWSPCAIssuer with template <templateArn> using a <caType> CA
      When I issue a <certType> certificate with usage <usage>
      Then the certificate should be issued successfully
      And the CA certificate should have path length <pathLen>

      Examples:
        | caType   | certType | templateArn                                               | usage        | pathLen |
        | RSA      | ECDSA    | SubordinateCACertificate_PathLen0/V1                      | any          | 0       |
        | RSA      | ECDSA    | SubordinateCACertificate_PathLen1/V1                      | any          | 1       |
        | RSA      | ECDSA    | SubordinateCACertificate_PathLen2/V1                      | any          | 2       |
        | RSA      | ECDSA    | SubordinateCACertificate_PathLen3/V1                      | any          | 3       |
        | RSA      | ECDSA    | SubordinateCACertificate_PathLen3_APICSRPassthrough/V1    | any          | 3       |
        | RSA      | ECDSA    | BlankSubordinateCACertificate_PathLen3_APIPassthrough/V1  | any          | 3       |
        | RSA-SUB  | ECDSA    | SubordinateCACertificate_PathLen0/V1                      | any          | 0       |

    @NegativeCATests
      Scenario Outline: Issue certificate with specific template
        Given I create an AWSPCAIssuer with template <templateArn> using a <caType> CA
        When I issue a <certType> certificate
        Then the certificate request has reason Failed and status False

        Examples:
          | caType       | certType   | templateArn                                           | usage     |
          | RSA          | RSA        | InvalidTemplateArn                                    | any       |
          | ECDSA-SUB    | ECDSA      | SubordinateCACertificate_PathLen3/V1                  | any       |
          | RSA-SUB      | RSA        | SubordinateCACertificate_PathLen2/V1                  | any       |
        


