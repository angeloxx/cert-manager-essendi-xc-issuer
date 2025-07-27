package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConditionStatus_Values(t *testing.T) {
	tests := []struct {
		name     string
		status   ConditionStatus
		expected string
	}{
		{
			name:     "ConditionTrue",
			status:   ConditionTrue,
			expected: "True",
		},
		{
			name:     "ConditionFalse",
			status:   ConditionFalse,
			expected: "False",
		},
		{
			name:     "ConditionUnknown",
			status:   ConditionUnknown,
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.status))
		})
	}
}

func TestIssuerConditionType_Values(t *testing.T) {
	assert.Equal(t, "Ready", string(IssuerConditionReady))
}

func TestTaskStatus_Constants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{
			name:     "TaskStatusProcessing",
			constant: TaskStatusProcessing,
			expected: "PROCESSING",
		},
		{
			name:     "TaskStatusApproved",
			constant: TaskStatusApproved,
			expected: "APPROVED",
		},
		{
			name:     "TaskStatusIssued",
			constant: TaskStatusIssued,
			expected: "ISSUED",
		},
		{
			name:     "TaskStatusFailed",
			constant: TaskStatusFailed,
			expected: "FAILED_IN_REVIEW",
		},
		{
			name:     "TaskStatusDeclined",
			constant: TaskStatusDeclined,
			expected: "DECLINED",
		},
		{
			name:     "TaskStatusCanceled",
			constant: TaskStatusCanceled,
			expected: "CANCELED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestIssuerConditionStatus_Constants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{
			name:     "IssuerConditionStatusSubmitted",
			constant: IssuerConditionStatusSubmitted,
			expected: "Certificate request submitted",
		},
		{
			name:     "IssuerConditionStatusProcessing",
			constant: IssuerConditionStatusProcessing,
			expected: "Certificate request in progress",
		},
		{
			name:     "IssuerConditionStatusApproved",
			constant: IssuerConditionStatusApproved,
			expected: "Certificate request approved",
		},
		{
			name:     "IssuerConditionStatusSigned",
			constant: IssuerConditionStatusSigned,
			expected: "Certificate is signed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestEventConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{
			name:     "EventSource",
			constant: EventSource,
			expected: "essendi-xc-issuer",
		},
		{
			name:     "EventReasonCertificateRequestReconciler",
			constant: EventReasonCertificateRequestReconciler,
			expected: "CertificateRequestReconciler",
		},
		{
			name:     "EventReasonIssuerReconciler",
			constant: EventReasonIssuerReconciler,
			expected: "IssuerReconciler",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}