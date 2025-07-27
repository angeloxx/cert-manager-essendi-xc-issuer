package v1alpha1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIssuerSpec_Validation(t *testing.T) {
	tests := []struct {
		name  string
		spec  IssuerSpec
		valid bool
	}{
		{
			name: "valid-spec",
			spec: IssuerSpec{
				URL:            "https://example.com",
				ProfileName:    "test-profile",
				SubscriberName: "test-subscriber",
				AuthSecretName: "test-secret",
			},
			valid: true,
		},
		{
			name: "valid-spec-with-custom-fields",
			spec: IssuerSpec{
				URL:            "https://example.com",
				ProfileName:    "test-profile",
				SubscriberName: "test-subscriber",
				AuthSecretName: "test-secret",
				CustomFields: []IssuerCustomField{
					{Name: "field1", Value: "value1"},
					{Name: "field2", Value: "value2"},
				},
			},
			valid: true,
		},
		{
			name: "valid-spec-with-ignore-host-flag",
			spec: IssuerSpec{
				URL:                     "https://example.com",
				ProfileName:             "test-profile",
				SubscriberName:          "test-subscriber",
				AuthSecretName:          "test-secret",
				IgnoreHostInApiResponse: true,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling/unmarshaling
			data, err := json.Marshal(tt.spec)
			require.NoError(t, err)

			var unmarshaledSpec IssuerSpec
			err = json.Unmarshal(data, &unmarshaledSpec)
			require.NoError(t, err)

			assert.Equal(t, tt.spec.URL, unmarshaledSpec.URL)
			assert.Equal(t, tt.spec.ProfileName, unmarshaledSpec.ProfileName)
			assert.Equal(t, tt.spec.SubscriberName, unmarshaledSpec.SubscriberName)
			assert.Equal(t, tt.spec.AuthSecretName, unmarshaledSpec.AuthSecretName)
			assert.Equal(t, tt.spec.IgnoreHostInApiResponse, unmarshaledSpec.IgnoreHostInApiResponse)
			assert.Equal(t, len(tt.spec.CustomFields), len(unmarshaledSpec.CustomFields))
		})
	}
}

func TestIssuerCustomField_Serialization(t *testing.T) {
	customField := IssuerCustomField{
		Name:  "test-field",
		Value: "test-value",
	}

	data, err := json.Marshal(customField)
	require.NoError(t, err)

	var unmarshaledField IssuerCustomField
	err = json.Unmarshal(data, &unmarshaledField)
	require.NoError(t, err)

	assert.Equal(t, customField.Name, unmarshaledField.Name)
	assert.Equal(t, customField.Value, unmarshaledField.Value)
}

func TestIssuerCondition_Serialization(t *testing.T) {
	now := metav1.Now()
	condition := IssuerCondition{
		Type:               IssuerConditionReady,
		Status:             ConditionTrue,
		LastTransitionTime: &now,
		Reason:             "TestReason",
		Message:            "Test message",
	}

	data, err := json.Marshal(condition)
	require.NoError(t, err)

	var unmarshaledCondition IssuerCondition
	err = json.Unmarshal(data, &unmarshaledCondition)
	require.NoError(t, err)

	assert.Equal(t, condition.Type, unmarshaledCondition.Type)
	assert.Equal(t, condition.Status, unmarshaledCondition.Status)
	assert.Equal(t, condition.Reason, unmarshaledCondition.Reason)
	assert.Equal(t, condition.Message, unmarshaledCondition.Message)
	// Time comparison - just check that it's not nil
	assert.NotNil(t, unmarshaledCondition.LastTransitionTime)
}

func TestIssuer_DefaultValues(t *testing.T) {
	issuer := &Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-issuer",
			Namespace: "test-namespace",
		},
		Spec: IssuerSpec{
			URL:            "https://example.com",
			ProfileName:    "test-profile",
			SubscriberName: "test-subscriber",
			AuthSecretName: "test-secret",
		},
	}

	// Test that the issuer can be created without errors
	assert.Equal(t, "test-issuer", issuer.Name)
	assert.Equal(t, "test-namespace", issuer.Namespace)
	assert.Equal(t, "https://example.com", issuer.Spec.URL)
	assert.False(t, issuer.Spec.IgnoreHostInApiResponse) // Default should be false
	assert.Empty(t, issuer.Spec.CustomFields)            // Default should be empty
	assert.Empty(t, issuer.Status.Conditions)           // Default should be empty
}

func TestIssuer_WithConditions(t *testing.T) {
	now := metav1.Now()
	issuer := &Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-issuer",
			Namespace: "test-namespace",
		},
		Spec: IssuerSpec{
			URL:            "https://example.com",
			ProfileName:    "test-profile",
			SubscriberName: "test-subscriber",
			AuthSecretName: "test-secret",
		},
		Status: IssuerStatus{
			Conditions: []IssuerCondition{
				{
					Type:               IssuerConditionReady,
					Status:             ConditionTrue,
					LastTransitionTime: &now,
					Reason:             "Provisioned",
					Message:            "Issuer is ready",
				},
			},
		},
	}

	assert.Len(t, issuer.Status.Conditions, 1)
	condition := issuer.Status.Conditions[0]
	assert.Equal(t, IssuerConditionReady, condition.Type)
	assert.Equal(t, ConditionTrue, condition.Status)
	assert.Equal(t, "Provisioned", condition.Reason)
	assert.Equal(t, "Issuer is ready", condition.Message)
}

func TestClusterIssuer_DefaultValues(t *testing.T) {
	clusterIssuer := &ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-issuer",
		},
		Spec: IssuerSpec{
			URL:            "https://example.com",
			ProfileName:    "test-profile",
			SubscriberName: "test-subscriber",
			AuthSecretName: "test-secret",
		},
	}

	// Test that the cluster issuer can be created without errors
	assert.Equal(t, "test-cluster-issuer", clusterIssuer.Name)
	assert.Empty(t, clusterIssuer.Namespace) // ClusterIssuer should not have namespace
	assert.Equal(t, "https://example.com", clusterIssuer.Spec.URL)
	assert.False(t, clusterIssuer.Spec.IgnoreHostInApiResponse) // Default should be false
	assert.Empty(t, clusterIssuer.Spec.CustomFields)            // Default should be empty
	assert.Empty(t, clusterIssuer.Status.Conditions)           // Default should be empty
}

func TestIssuerList_Serialization(t *testing.T) {
	issuerList := &IssuerList{
		Items: []Issuer{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "issuer1",
					Namespace: "test-namespace",
				},
				Spec: IssuerSpec{
					URL:            "https://example1.com",
					ProfileName:    "profile1",
					SubscriberName: "subscriber1",
					AuthSecretName: "secret1",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "issuer2",
					Namespace: "test-namespace",
				},
				Spec: IssuerSpec{
					URL:            "https://example2.com",
					ProfileName:    "profile2",
					SubscriberName: "subscriber2",
					AuthSecretName: "secret2",
				},
			},
		},
	}

	data, err := json.Marshal(issuerList)
	require.NoError(t, err)

	var unmarshaledList IssuerList
	err = json.Unmarshal(data, &unmarshaledList)
	require.NoError(t, err)

	assert.Len(t, unmarshaledList.Items, 2)
	assert.Equal(t, "issuer1", unmarshaledList.Items[0].Name)
	assert.Equal(t, "issuer2", unmarshaledList.Items[1].Name)
}

func TestClusterIssuerList_Serialization(t *testing.T) {
	clusterIssuerList := &ClusterIssuerList{
		Items: []ClusterIssuer{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster-issuer1",
				},
				Spec: IssuerSpec{
					URL:            "https://example1.com",
					ProfileName:    "profile1",
					SubscriberName: "subscriber1",
					AuthSecretName: "secret1",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster-issuer2",
				},
				Spec: IssuerSpec{
					URL:            "https://example2.com",
					ProfileName:    "profile2",
					SubscriberName: "subscriber2",
					AuthSecretName: "secret2",
				},
			},
		},
	}

	data, err := json.Marshal(clusterIssuerList)
	require.NoError(t, err)

	var unmarshaledList ClusterIssuerList
	err = json.Unmarshal(data, &unmarshaledList)
	require.NoError(t, err)

	assert.Len(t, unmarshaledList.Items, 2)
	assert.Equal(t, "cluster-issuer1", unmarshaledList.Items[0].Name)
	assert.Equal(t, "cluster-issuer2", unmarshaledList.Items[1].Name)
}