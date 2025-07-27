/*
Copyright 2020 The cert-manager Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	essendixcissuerapi "github.com/angeloxx/cert-manager-essendi-xc-issuer/api/v1alpha1"
)

func TestSetReadyCondition(t *testing.T) {
	var issuerStatus essendixcissuerapi.IssuerStatus

	// Test setting condition for the first time
	SetReadyCondition(&issuerStatus, essendixcissuerapi.ConditionTrue, "reason1", "message1")
	assert.Len(t, issuerStatus.Conditions, 1)
	condition := GetReadyCondition(&issuerStatus)
	require.NotNil(t, condition)
	assert.Equal(t, "message1", condition.Message)
	assert.Equal(t, "reason1", condition.Reason)
	assert.Equal(t, essendixcissuerapi.ConditionTrue, condition.Status)
	assert.Equal(t, essendixcissuerapi.IssuerConditionReady, condition.Type)
	assert.NotNil(t, condition.LastTransitionTime)

	// Store the first transition time
	firstTransitionTime := condition.LastTransitionTime

	// Test updating condition with same status (should not update transition time)
	time.Sleep(time.Millisecond) // Ensure time difference
	SetReadyCondition(&issuerStatus, essendixcissuerapi.ConditionTrue, "reason2", "message2")
	assert.Len(t, issuerStatus.Conditions, 1)
	condition = GetReadyCondition(&issuerStatus)
	require.NotNil(t, condition)
	assert.Equal(t, "message2", condition.Message)
	assert.Equal(t, "reason2", condition.Reason)
	assert.Equal(t, essendixcissuerapi.ConditionTrue, condition.Status)
	assert.Equal(t, firstTransitionTime, condition.LastTransitionTime) // Should be same

	// Test updating condition with different status (should update transition time)
	time.Sleep(time.Millisecond) // Ensure time difference
	SetReadyCondition(&issuerStatus, essendixcissuerapi.ConditionFalse, "reason3", "message3")
	assert.Len(t, issuerStatus.Conditions, 1)
	condition = GetReadyCondition(&issuerStatus)
	require.NotNil(t, condition)
	assert.Equal(t, "message3", condition.Message)
	assert.Equal(t, "reason3", condition.Reason)
	assert.Equal(t, essendixcissuerapi.ConditionFalse, condition.Status)
	assert.True(t, condition.LastTransitionTime.After(firstTransitionTime.Time)) // Should be updated
}

func TestGetReadyCondition(t *testing.T) {
	tests := []struct {
		name       string
		status     essendixcissuerapi.IssuerStatus
		expectNil  bool
		expectType essendixcissuerapi.IssuerConditionType
	}{
		{
			name:      "no-conditions",
			status:    essendixcissuerapi.IssuerStatus{},
			expectNil: true,
		},
		{
			name: "has-ready-condition",
			status: essendixcissuerapi.IssuerStatus{
				Conditions: []essendixcissuerapi.IssuerCondition{
					{
						Type:   essendixcissuerapi.IssuerConditionReady,
						Status: essendixcissuerapi.ConditionTrue,
					},
				},
			},
			expectNil:  false,
			expectType: essendixcissuerapi.IssuerConditionReady,
		},
		{
			name: "has-other-condition",
			status: essendixcissuerapi.IssuerStatus{
				Conditions: []essendixcissuerapi.IssuerCondition{
					{
						Type:   "SomeOtherType",
						Status: essendixcissuerapi.ConditionTrue,
					},
				},
			},
			expectNil: true,
		},
		{
			name: "has-multiple-conditions-with-ready",
			status: essendixcissuerapi.IssuerStatus{
				Conditions: []essendixcissuerapi.IssuerCondition{
					{
						Type:   "SomeOtherType",
						Status: essendixcissuerapi.ConditionTrue,
					},
					{
						Type:   essendixcissuerapi.IssuerConditionReady,
						Status: essendixcissuerapi.ConditionFalse,
					},
				},
			},
			expectNil:  false,
			expectType: essendixcissuerapi.IssuerConditionReady,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := GetReadyCondition(&tt.status)
			if tt.expectNil {
				assert.Nil(t, condition)
			} else {
				require.NotNil(t, condition)
				assert.Equal(t, tt.expectType, condition.Type)
			}
		})
	}
}

func TestGetSpecAndStatus(t *testing.T) {
	tests := []struct {
		name        string
		issuer      client.Object
		expectError bool
		expectSpec  *essendixcissuerapi.IssuerSpec
		expectURL   string
	}{
		{
			name: "issuer",
			issuer: &essendixcissuerapi.Issuer{
				Spec: essendixcissuerapi.IssuerSpec{
					URL: "https://example.com",
				},
			},
			expectError: false,
			expectURL:   "https://example.com",
		},
		{
			name: "cluster-issuer",
			issuer: &essendixcissuerapi.ClusterIssuer{
				Spec: essendixcissuerapi.IssuerSpec{
					URL: "https://cluster.example.com",
				},
			},
			expectError: false,
			expectURL:   "https://cluster.example.com",
		},
		{
			name:        "invalid-type",
			issuer:      &v1.Certificate{}, // Wrong type
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, status, err := GetSpecAndStatus(tt.issuer)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, spec)
				assert.Nil(t, status)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, spec)
				require.NotNil(t, status)
				assert.Equal(t, tt.expectURL, spec.URL)
			}
		})
	}
}

func TestIsReady(t *testing.T) {
	tests := []struct {
		name     string
		status   *essendixcissuerapi.IssuerStatus
		expected bool
	}{
		{
			name:     "no-conditions",
			status:   &essendixcissuerapi.IssuerStatus{},
			expected: false,
		},
		{
			name: "ready-true",
			status: &essendixcissuerapi.IssuerStatus{
				Conditions: []essendixcissuerapi.IssuerCondition{
					{
						Type:   essendixcissuerapi.IssuerConditionReady,
						Status: essendixcissuerapi.ConditionTrue,
					},
				},
			},
			expected: true,
		},
		{
			name: "ready-false",
			status: &essendixcissuerapi.IssuerStatus{
				Conditions: []essendixcissuerapi.IssuerCondition{
					{
						Type:   essendixcissuerapi.IssuerConditionReady,
						Status: essendixcissuerapi.ConditionFalse,
					},
				},
			},
			expected: false,
		},
		{
			name: "ready-unknown",
			status: &essendixcissuerapi.IssuerStatus{
				Conditions: []essendixcissuerapi.IssuerCondition{
					{
						Type:   essendixcissuerapi.IssuerConditionReady,
						Status: essendixcissuerapi.ConditionUnknown,
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsReady(tt.status)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCertificateRequestConditions(t *testing.T) {
	now := metav1.Now()
	
	tests := []struct {
		name     string
		status   *v1.CertificateRequestStatus
		testFunc func(*v1.CertificateRequestStatus) bool
		expected bool
	}{
		{
			name: "is-submitted-true",
			status: &v1.CertificateRequestStatus{
				Conditions: []v1.CertificateRequestCondition{
					{
						Type:               v1.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "Pending",
						Message:            essendixcissuerapi.IssuerConditionStatusSubmitted + ", status: task-123",
					},
				},
			},
			testFunc: IsSubmitted,
			expected: true,
		},
		{
			name: "is-submitted-false",
			status: &v1.CertificateRequestStatus{
				Conditions: []v1.CertificateRequestCondition{
					{
						Type:               v1.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "Pending",
						Message:            "Some other message",
					},
				},
			},
			testFunc: IsSubmitted,
			expected: false,
		},
		{
			name: "is-approved-true",
			status: &v1.CertificateRequestStatus{
				Conditions: []v1.CertificateRequestCondition{
					{
						Type:               v1.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "Pending",
						Message:            essendixcissuerapi.IssuerConditionStatusApproved + ", resource: task-123",
					},
				},
			},
			testFunc: IsApproved,
			expected: true,
		},
		{
			name: "is-processing-true",
			status: &v1.CertificateRequestStatus{
				Conditions: []v1.CertificateRequestCondition{
					{
						Type:               v1.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "Pending",
						Message:            essendixcissuerapi.IssuerConditionStatusProcessing + ", resource: task-123",
					},
				},
			},
			testFunc: IsProcessing,
			expected: true,
		},
		{
			name: "is-signed-true",
			status: &v1.CertificateRequestStatus{
				Conditions: []v1.CertificateRequestCondition{
					{
						Type:               v1.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "Pending",
						Message:            essendixcissuerapi.IssuerConditionStatusSigned + ", resource: cert-456",
					},
				},
			},
			testFunc: IsSigned,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.testFunc(tt.status)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetSubmittedCondition(t *testing.T) {
	now := metav1.Now()
	
	tests := []struct {
		name        string
		status      *v1.CertificateRequestStatus
		expectFound bool
		expectMsg   string
	}{
		{
			name: "has-submitted-condition",
			status: &v1.CertificateRequestStatus{
				Conditions: []v1.CertificateRequestCondition{
					{
						Type:               v1.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "Pending",
						Message:            essendixcissuerapi.IssuerConditionStatusSubmitted + ", status: task-123",
					},
				},
			},
			expectFound: true,
			expectMsg:   essendixcissuerapi.IssuerConditionStatusSubmitted + ", status: task-123",
		},
		{
			name: "has-approved-condition",
			status: &v1.CertificateRequestStatus{
				Conditions: []v1.CertificateRequestCondition{
					{
						Type:               v1.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "Pending",
						Message:            essendixcissuerapi.IssuerConditionStatusApproved + ", resource: task-123",
					},
				},
			},
			expectFound: true,
			expectMsg:   essendixcissuerapi.IssuerConditionStatusApproved + ", resource: task-123",
		},
		{
			name: "no-matching-condition",
			status: &v1.CertificateRequestStatus{
				Conditions: []v1.CertificateRequestCondition{
					{
						Type:               v1.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionTrue,
						LastTransitionTime: &now,
						Reason:             "Issued",
						Message:            "Certificate issued successfully",
					},
				},
			},
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := GetSubmittedCondition(tt.status)
			if tt.expectFound {
				require.NotNil(t, condition)
				assert.Equal(t, tt.expectMsg, condition.Message)
			} else {
				assert.Nil(t, condition)
			}
		})
	}
}

func TestGetSignedCondition(t *testing.T) {
	now := metav1.Now()
	
	tests := []struct {
		name        string
		status      *v1.CertificateRequestStatus
		expectFound bool
		expectMsg   string
	}{
		{
			name: "has-signed-condition",
			status: &v1.CertificateRequestStatus{
				Conditions: []v1.CertificateRequestCondition{
					{
						Type:               v1.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "Pending",
						Message:            essendixcissuerapi.IssuerConditionStatusSigned + ", resource: cert-456",
					},
				},
			},
			expectFound: true,
			expectMsg:   essendixcissuerapi.IssuerConditionStatusSigned + ", resource: cert-456",
		},
		{
			name: "no-signed-condition",
			status: &v1.CertificateRequestStatus{
				Conditions: []v1.CertificateRequestCondition{
					{
						Type:               v1.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "Pending",
						Message:            essendixcissuerapi.IssuerConditionStatusSubmitted + ", status: task-123",
					},
				},
			},
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := GetSignedCondition(tt.status)
			if tt.expectFound {
				require.NotNil(t, condition)
				assert.Equal(t, tt.expectMsg, condition.Message)
			} else {
				assert.Nil(t, condition)
			}
		})
	}
}
