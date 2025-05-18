# essendi-xc-issuer

Essendi-XC Issuer is a cert-manager's CertificateRequest controller that uses [Essendi XC](https://xc.essendi.de/en/essendi-xc/]) 
to sign certificates. Essendi XC is a service that provides multiple interfaces for requesting certificates from different CAs,
like Microsoft ADCS or public CAs like D-Trust, DigiCert, QuoVadis, SwissSign. Essendi XC provides both ACME, SCEP and proprietary REST
API; This implementation is a HTTP client that interacts with the Essendi XC API sending appropriately 
prepared HTTP requests and interpreting the server's HTTP responses.

## Requirements

Current operator version was tested with the following versions of the dependencies:

| Component    | Tested versions |
|--------------|-----------------|
| Kubernetes   | 1.29 .. 1.30    |
| cert-manager | 1.15 .. 1.16    |
| Essendi XC   | 1.26.2          |

and currently supports CertificateRequest CRD API version v1 only.

# Configuration and usage
## Issuers

The Essendi-XC service data can be configured in Issuer or ClusterIssuer CRD objects e.g.:

```yaml
apiVersion: essendixc.angeloxx.ch/v1alpha1
kind: ClusterIssuer
metadata:
  name: test-integration
spec:
  authSecretName: <auth-secret-reference-in-cert-manager-namespace>
  ignoreHostInApiResponse: true|false
  profileName: <issuing-profile-name>
  subscriberName: <subscriber-name>
  url: <essendi-xc-api-url>
```

Required parameters are:
* authSecretName: name of the secret that contains the credentials used to authenticate with the Essendi XC API
* ignoreHostInApiResponse: if set to true, the issuer will ignore the host in the API response. This is useful when using a load balancer or reverse proxy in front of the Essendi XC API.
* profileName: name of the profile defined in the Essendi XC. This is the profile that will be used to issue the certificate.
* subscriberName: name of the subscriber defined in the Essendi XC.
* url: the base URL of the Essendi XC API server.

optionally you can define also a set of custom fields that will be passed to the Essendi XC API and added as metadata to all the requests. Custom fields must be previously defined in the Essendi XC, then the CRD can be used to set it, eg:

```yaml
apiVersion: essendixc.angeloxx.ch/v1alpha1
kind: ClusterIssuer
metadata:
  name: test-integration
spec:
  authSecretName: <auth-secret-reference-in-cert-manager-namespace>
  ignoreHostInApiResponse: true|false
  profileName: <issuing-profile-name>
  subscriberName: <subscriber-name>
  url: <essendi-xc-api-url>
  customFields:
  - name: Application
    value: '{{ .Csr.CommonName }}'
  - name: DeploymentTarget
    value: Kubernetes
  - name: Environment
    value: Testing Environment
  - name: NotificationMail
    value: cloudnatives@bigcorp.ch
```

You have also to define the secret containing the credentials used to authenticate with the Essendi XC API. The secret must be in the same namespace as the cert-manager controller:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: essendixc-cert-manager
  namespace: cert-manager
data:
  client-id: <essendi-xc-client-id>
  client-secret: <client-secret>
  signature-key: <request-signature-key>
  token: eyJhbGciOiJIUzI1NiIsInR5cCIgOi[...]
```

The secret must be Opaque and contain the following fields:
* client-id: the client ID used to authenticate with the Essendi XC API
* client-secret: the client secret used to authenticate with the Essendi XC API
* signature-key: the key used to sign the request
* token: the token used to authenticate

### Template support for customFields

CustomFields can be used to pass additional information to the Essendi-XC API. The customFields are rendered using Go templates and
you can use the following variables:

* Csr.CommonName: the common name of the requested certificate
* Csr.Organization: the organization of the requested certificate
* Csr.OrganizationalUnit: the organizational unit of the requested certificate
* Csr.Country: the country of the requested certificate
* Csr.Locality: the locality of the requested certificate
* Csr.Province: the province of the requested certificate
* Issuer.ProfileName: the profile name of the issuer
* Issuer.SubscriberName: the subscriber name of the issuer

## Install

We recommend to use the Helm chart to install the Essendi-XC Issuer. The Helm chart is available in the [cert-manager Helm repository](https://artifacthub.io/packages/search?kind=0&repo=cert-manager).

```console
helm install essendi-xc-issuer oci://registry-1.docker.io/angeloxx/cert-manager-essendi-xc-issuer --version <version>-helm --namespace cert-manager
```

# See also

* [When cert-manager meets Essendi XC](https://medium.com/@angeloxx/when-cert-manager-meets-essendi-xc-7783e4f0fb42)

# License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
