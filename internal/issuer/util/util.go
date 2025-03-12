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
	"fmt"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	essendixcissuerapi "github.com/angeloxx/cert-manager-essendi-xc-issuer/api/v1alpha1"
)

func GetSpecAndStatus(issuer client.Object) (*essendixcissuerapi.IssuerSpec, *essendixcissuerapi.IssuerStatus, error) {
	switch t := issuer.(type) {
	case *essendixcissuerapi.Issuer:
		return &t.Spec, &t.Status, nil
	case *essendixcissuerapi.ClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an issuer type: %t", t)
	}
}

func SetReadyCondition(status *essendixcissuerapi.IssuerStatus, conditionStatus essendixcissuerapi.ConditionStatus, reason, message string) {
	ready := GetReadyCondition(status)
	if ready == nil {
		ready = &essendixcissuerapi.IssuerCondition{
			Type: essendixcissuerapi.IssuerConditionReady,
		}
		status.Conditions = append(status.Conditions, *ready)
	}
	if ready.Status != conditionStatus {
		ready.Status = conditionStatus
		now := metav1.Now()
		ready.LastTransitionTime = &now
	}
	ready.Reason = reason
	ready.Message = message

	for i, c := range status.Conditions {
		if c.Type == essendixcissuerapi.IssuerConditionReady {
			status.Conditions[i] = *ready
			return
		}
	}
}

func GetReadyCondition(status *essendixcissuerapi.IssuerStatus) *essendixcissuerapi.IssuerCondition {
	for _, c := range status.Conditions {
		if c.Type == essendixcissuerapi.IssuerConditionReady {
			return &c
		}
	}
	return nil
}

func GetSubmittedCondition(status *v1.CertificateRequestStatus) *v1.CertificateRequestCondition {
	for _, c := range status.Conditions {
		if strings.HasPrefix(c.Message, essendixcissuerapi.IssuerConditionStatusSubmitted) || strings.HasPrefix(c.Message, essendixcissuerapi.IssuerConditionStatusApproved) || strings.HasPrefix(c.Message, essendixcissuerapi.IssuerConditionStatusProcessing) {
			return &c
		}
	}
	return nil
}

func GetSignedCondition(status *v1.CertificateRequestStatus) *v1.CertificateRequestCondition {
	for _, c := range status.Conditions {
		if strings.HasPrefix(c.Message, essendixcissuerapi.IssuerConditionStatusSigned) {
			return &c
		}
	}
	return nil
}

func IsReady(status *essendixcissuerapi.IssuerStatus) bool {
	if c := GetReadyCondition(status); c != nil {
		return c.Status == essendixcissuerapi.ConditionTrue
	}
	return false
}

func IsSubmitted(status *v1.CertificateRequestStatus) bool {
	if c := GetSubmittedCondition(status); c != nil {
		return true
	}
	return false
}

func IsApproved(status *v1.CertificateRequestStatus) bool {
	if c := GetSubmittedCondition(status); c != nil {
		if strings.HasPrefix(c.Message, essendixcissuerapi.IssuerConditionStatusApproved) {
			return true
		}
	}
	return false
}
func IsProcessing(status *v1.CertificateRequestStatus) bool {
	if c := GetSubmittedCondition(status); c != nil {
		if strings.HasPrefix(c.Message, essendixcissuerapi.IssuerConditionStatusProcessing) {
			return true
		}
	}
	return false
}

func IsSigned(status *v1.CertificateRequestStatus) bool {
	if c := GetSignedCondition(status); c != nil {
		return true
	}
	return false
}
