# essendi-xc-issuer

Essendi-XC Issuer is a cert-manager's CertificateRequest controller that uses [Essendi XC](https://xc.essendi.de/en/essendi-xc/]) 
to sign certificates. Essendi XC is a service that provides multiple interfaces for requesting certificates from different CAs,
like Microsoft ADCS or public CAs like D-Trust, DigiCert, QuoVadis, SwissSign. Essendi XC provides both ACME, SCEP and proprietary REST
API; This implementation is a HTTP client that interacts with the Essendi XC API sending appropriately 
prepared HTTP requests and interpreting the server's HTTP responses.

## Requirements

Essendi-XC Issuer has been tested with cert-manager v.1.13.0 and currently supports CertificateRequest CRD API version v1 only.

# Configuration and usage
## Issuers

The Essendi-XC service data can be configured in EssendiXCIssuer or ClusterEssendiXCIssuer CRD objects e.g.:

```yaml
apiVersion: essendixc.angeloxx.ch/v1
kind: ClusterEssendiXCIssuer
metadata:
  name: test-integration
  namespace: <namespace>
spec:
  credentialsRef:
    name: essendi-xc-issuer-credentials
  url: <essendi-xc-api-url>
  profileName: <issuing-profile-name>
  subscriberName: <subscriber-name>
  realm: <authentication-realm>
```

The caBundle parameter is BASE64-encoded CA certificate which is used by the ADCS server itself, which may not be the same certificate that will be used to sign your request.

The statusCheckInterval indicates how often the status of the request should be tested. Typically, it can take a few hours or even days before the certificate is issued.

The retryInterval says how long to wait before retrying requests that errored.

The credentialsRef.name is name of a secret that stores user credentials used for NTLM authentication. The secret must be Opaque and contain password and username fields only e.g.:

```yaml
apiVersion: v1
data:
  clientId: my-essendi-user
  offlineToken: eyJhbGciOiJIUzI1NiIsInR5cCIgOi...
kind: Secret
metadata:
  name: essendi-xc-issuer-credentials
  namespace: <namespace>
type: Opaque
```

If cluster level issuer configuration is needed then ClusterAdcsUssuer can be defined like this:

```yaml
apiVersion: essendixc.certmanager.angeloxx.ch/v1
kind: ClusterAdcsIssuer
metadata:
  name: test-adcs
spec:
  caBundle: <base64-encoded-ca-certificate>
  credentialsRef:
    name: test-essendixc-issuer-credentials
  statusCheckInterval: 6h
  retryInterval: 1h
  url: <essendixc-api-url>
  profileName: <issuing-profile-name>
  subscriberName: <subscriber-name>
  customFields:
    field1: value1
    field2: value2
    field3: {{ .Csr.CommonName }}
```

The secret used by the ClusterEssendiXCIssuer to authenticate (credentialsRef), must be defined in the namespace 
where the controller's pod is running, or in the namespace specified by the flag -clusterResourceNamespace (default: kube-system).

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
helm install essendi-xc-issuer oci://registry-1.docker.io/angeloxx/cert-manager-essendi-issuer --version <version>-helm --namespace cert-manager
```

# License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
