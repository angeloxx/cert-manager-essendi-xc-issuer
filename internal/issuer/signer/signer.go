package signer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	essendixcissuerapi "github.com/angeloxx/cert-manager-essendi-xc-issuer/api/v1alpha1"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"regexp"
	ctrl "sigs.k8s.io/controller-runtime"
	"strings"
	"text/template"
	"time"
)

var (
	errGetAuthSecret = errors.New("error getting auth secret")
)

type EssendiXCIssuingError struct {
	Definitive bool
	Msg        string
}

func (e *EssendiXCIssuingError) Error() string {
	return e.Msg
}
func (e *EssendiXCIssuingError) IsDefinitive() bool {
	return e.Definitive
}

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*essendixcissuerapi.IssuerSpec, map[string][]byte) (HealthChecker, error)

type Signer interface {
	// Sign([]byte) ([]byte, EssendiXCIssuingError)
	SubmitCertificateRequest(string, []byte) (string, error)
	GetRefreshToken() (string, error)
	RequestTaskStatus(string, string) (string, string, error)
	FetchCertificate(string, string) ([]byte, error)
}

type SignerBuilder func(context.Context, *essendixcissuerapi.IssuerSpec, string, map[string][]byte) (Signer, error)

func EssendiHealthCheckerFromIssuerAndSecretData(*essendixcissuerapi.IssuerSpec, map[string][]byte) (HealthChecker, error) {
	return &essendixcSigner{}, nil
}

func EssendiSignerFromIssuerAndSecretData(c context.Context, issuer *essendixcissuerapi.IssuerSpec, authRealm string, secret map[string][]byte) (Signer, error) {
	clientID, ok := secret["client-id"]
	if !ok {
		return nil, fmt.Errorf("%s not found in secret", "client-id")
	}

	clientSecret, ok := secret["client-secret"]
	if !ok {
		return nil, fmt.Errorf("%s not found in secret", "client-secret")
	}

	token, ok := secret["token"]
	if !ok {
		return nil, fmt.Errorf("%s not found in secret", "token")
	}

	signatureKey, ok := secret["signature-key"]
	if !ok {
		return nil, fmt.Errorf("%s not found in secret", "signature-key")
	}

	return &essendixcSigner{c, issuer, string(clientID), string(clientSecret), string(token), authRealm, string(signatureKey)}, nil
}

type essendixcSigner struct {
	ctx          context.Context
	issuer       *essendixcissuerapi.IssuerSpec
	clientID     string
	clientSecret string
	token        string
	realm        string
	signatureKey string
}

func (o *essendixcSigner) Check() error {
	return nil
}

func (o *essendixcSigner) GetRefreshToken() (string, error) {
	ctx := context.Background()

	conf := &oauth2.Config{
		ClientID:     o.clientID,
		ClientSecret: o.clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: o.issuer.URL + "/auth/realms/" + o.realm + "/protocol/openid-connect/token",
		},
	}

	tok := &oauth2.Token{
		RefreshToken: string(o.token),
	}

	tokenSource := conf.TokenSource(ctx, tok)
	token, err := tokenSource.Token()
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

func (o *essendixcSigner) SubmitCertificateRequest(token string, csrBytes []byte) (string, error) {
	// Convert the CSR bytes to a string
	log := ctrl.LoggerFrom(o.ctx)
	csrRequest, err := parseCSR(csrBytes)

	if err != nil {
		return "", err
	}

	csrCountry := ""
	if len(csrRequest.Subject.Country) > 0 {
		csrCountry = csrRequest.Subject.Country[0]
	}
	csrLocality := ""
	if len(csrRequest.Subject.Locality) > 0 {
		csrLocality = csrRequest.Subject.Locality[0]
	}
	csrOrganization := ""
	if len(csrRequest.Subject.Organization) > 0 {
		csrOrganization = csrRequest.Subject.Organization[0]
	}
	csrOrganizationUnit := ""
	if len(csrRequest.Subject.OrganizationalUnit) > 0 {
		csrOrganizationUnit = csrRequest.Subject.OrganizationalUnit[0]
	}
	csrEmailAddress := ""
	if len(csrRequest.EmailAddresses) > 0 {
		csrEmailAddress = csrRequest.EmailAddresses[0]
	}
	csrProvince := ""
	if len(csrRequest.Subject.Province) > 0 {
		csrProvince = csrRequest.Subject.Province[0]
	}

	gotemplateVariables := map[string]interface{}{
		"Csr": map[string]string{
			"CommonName":         csrRequest.Subject.CommonName,
			"Country":            csrCountry,
			"Locality":           csrLocality,
			"Organization":       csrOrganization,
			"OrganizationalUnit": csrOrganizationUnit,
			"Email":              csrEmailAddress,
			"State":              csrProvince,
		},
		"Issuer": map[string]string{
			"ProfileName":    o.issuer.ProfileName,
			"SubscriberName": o.issuer.SubscriberName,
		},
	}
	log.Info("Ready to replace go template variables", "gotemplateVariables", gotemplateVariables)

	// Generate timestamp in Unixtime format
	timestamp := time.Now().Unix()
	apiUrl := "/api/v2/csr-process/request"

	// Converts customfields to the format expected by the API
	customFieldsMap := make(map[string]string)
	for _, field := range o.issuer.CustomFields {
		builder := &strings.Builder{}
		fieldTemplate, errTemplate := template.New("templateValue").Parse(field.Value)
		if errTemplate != nil {
			return "", errTemplate
		}

		errReplacer := fieldTemplate.Execute(builder, gotemplateVariables)
		if errReplacer != nil {
			return "", errReplacer
		}
		customFieldsMap[field.Name] = builder.String()
	}
	log.Info("Ready to set values for customFields", "customFieldsMap", customFieldsMap)

	// Define the data to be sent
	data := map[string]interface{}{
		"csr":         string(csrBytes),
		"profileName": o.issuer.ProfileName,
		"attributes": map[string]interface{}{
			"subject":                 map[string]interface{}{},
			"subjectAlternativeNames": []interface{}{},
		},
		"subscriber":   o.issuer.SubscriberName,
		"customFields": customFieldsMap,
	}
	// Convert the data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	xsignature := o.signEssendiApiRequest(
		o.clientID, "POST", "application/json", timestamp, apiUrl, string(jsonData), o.signatureKey)

	// Ready to send the request
	log.Info("Ready to send the request", "raw", data)

	// Create a new request
	req, err := http.NewRequest("POST", o.issuer.URL+apiUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	// Set the Content-Type header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-Signature", xsignature)

	// Send the request
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusAccepted {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error(err, "unable to read error body")
		}
		bodyString := string(bodyBytes)
		if json.Valid([]byte(bodyString)) {
			var response map[string]interface{}
			if err := json.Unmarshal([]byte(bodyString), &response); err == nil {
				if response["description"] != nil {
					return "", fmt.Errorf("%s (%d)", response["description"], resp.StatusCode)
				}
			}
		}
		return "", fmt.Errorf("unexpected status code: %d (%s)", resp.StatusCode, bodyString)
	}

	// Retrieve the Location header
	statusEndpointUrl := resp.Header.Get("Location")
	if statusEndpointUrl == "" {
		return "", fmt.Errorf("status endpoint URL not found")
	}

	if o.issuer.IgnoreHostInApiResponse {
		replaceRex := regexp.MustCompile(`^http[s]?://.*?/`)
		statusEndpointUrl = replaceRex.ReplaceAllString(statusEndpointUrl, o.issuer.URL+"/")
	}

	return statusEndpointUrl, nil

}

func (o *essendixcSigner) RequestTaskStatus(token string, statusEndpoint string) (string, string, error) {
	log := ctrl.LoggerFrom(o.ctx)

	// Parse statusEndpoint and get the request path
	parsedUrl, err := url.Parse(statusEndpoint)
	if err != nil {
		log.Error(err, "Error parsing status endpoint")
		return "", "", err
	}

	timestamp := time.Now().Unix()
	xsignature := o.signEssendiApiRequest(
		o.clientID, "GET", "application/json", timestamp, parsedUrl.Path, "", o.signatureKey)

	req, err := http.NewRequest("GET", statusEndpoint, nil)
	if err != nil {
		log.Error(err, "Error creating request")
		return "", "", err
	}

	// Set the Content-Type header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-Signature", xsignature)
	log.Info("4")
	// Send the request to the Status Endpoint
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	resp, err := client.Do(req)
	if err != nil {
		log.Error(err, "Error sending request")
		return "", "", nil

	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error(err, "unable to read error body")
	}
	bodyString := string(bodyBytes)
	requestStatus := ""
	if json.Valid([]byte(bodyString)) {
		var response map[string]string
		if err := json.Unmarshal([]byte(bodyString), &response); err == nil {
			if response["status"] != "" {
				/*
					Status is: PROCESSING, APPROVED, ISSUED, FAILED_IN_REVIEW, DECLINED, CANCELED
				*/
				requestStatus = response["status"]
			}
		}
	}
	// Check the response
	if resp.StatusCode != http.StatusSeeOther {
		log.Info("Task still not ready: " + bodyString)
		return "", requestStatus, nil
	}
	log.Info("Task is ready: " + bodyString)

	// Task ready, we can retrieve the certificate from the Resource Endpoint
	resourceEndpoint := resp.Header.Get("Location")
	if resourceEndpoint != "" {

		if o.issuer.IgnoreHostInApiResponse {
			replaceRex := regexp.MustCompile(`^http[s]?://.*?/`)
			resourceEndpoint = replaceRex.ReplaceAllString(resourceEndpoint, o.issuer.URL+"/")
		}
		return resourceEndpoint, requestStatus, nil
	}
	return "", "", nil
}

func (o *essendixcSigner) FetchCertificate(token string, resourceUrl string) ([]byte, error) {

	// Generate timestamp in Unixtime format
	timestamp := time.Now().Unix()
	parsedTaskUrl, _ := url.Parse(resourceUrl)

	xsignature := o.signEssendiApiRequest(
		o.clientID, "GET", "application/json", timestamp, parsedTaskUrl.Path, "", o.signatureKey)

	// Create a new request
	req, err := http.NewRequest("GET", resourceUrl, nil)
	if err != nil {
		return nil, err
	}

	// Set the Content-Type header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-Signature", xsignature)

	// Send the request
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("unable to read error body")
		}
		bodyString := string(bodyBytes)

		// if bodyString is a json, decode error from description
		if json.Valid([]byte(bodyString)) {
			var response map[string]interface{}
			if err := json.Unmarshal([]byte(bodyString), &response); err == nil {
				if response["description"] != nil {
					return nil, fmt.Errorf("unexpected status code: %d (%s)", resp.StatusCode, response["description"])
				}
			}
		}

		return nil, fmt.Errorf("unexpected status code: %d (%s)", resp.StatusCode, bodyString)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse the response body
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	// Retrieve the certificate
	certificate := response["data"].(string)
	if certificate == "" {
		return nil, fmt.Errorf("certificate not found")
	}

	return []byte(certificate), nil
}

func (o *essendixcSigner) generateXSignature(request string, signatureKey string) string {
	// Generate the HMAC-SHA256 signature
	h := hmac.New(sha256.New, []byte(signatureKey))
	h.Write([]byte(request))
	// signature := hex.EncodeToString(h.Sum(nil))

	// Return the signature
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (o *essendixcSigner) signEssendiApiRequest(clientId string, method string, contentType string, timestamp int64, urlpath string, data string, signatureKey string) string {
	return o.generateXSignature(
		fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n--\n%s\n--",
			clientId, method, contentType, fmt.Sprintf("%d", timestamp), urlpath, data),
		signatureKey)
}
