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

package controllers

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	essendixcissuerapi "github.com/angeloxx/cert-manager-essendi-xc-issuer/api/v1alpha1"
	"github.com/angeloxx/cert-manager-essendi-xc-issuer/internal/issuer/signer"
	issuerutil "github.com/angeloxx/cert-manager-essendi-xc-issuer/internal/issuer/util"
)

var (
	errIssuerRef      = errors.New("error interpreting issuerRef")
	errGetIssuer      = errors.New("error getting issuer")
	errIssuerNotReady = errors.New("issuer is not ready")
	errSignerBuilder  = errors.New("failed to build the signer")
	errSignerSign     = errors.New("failed to sign")
	errSignerRefused  = errors.New("signing refused")
)

// CertificateRequestReconciler reconciles a CertificateRequest object
type CertificateRequestReconciler struct {
	client.Client
	Scheme                   *runtime.Scheme
	SignerBuilder            signer.SignerBuilder
	ClusterResourceNamespace string
	AuthRealm                string
	Clock                    clock.Clock
	CheckApprovedCondition   bool
	recorder                 record.EventRecorder
}

func (r *CertificateRequestReconciler) Watchdog() (err error) {
	return nil
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	// Get the CertificateRequest
	var certificateRequest cmapi.CertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &certificateRequest); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Ignore CertificateRequest if issuerRef doesn't match our group
	if certificateRequest.Spec.IssuerRef.Group != essendixcissuerapi.GroupVersion.Group {
		log.Info("Foreign group. Ignoring.", "group", certificateRequest.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// Ignore CertificateRequest if it is already Ready
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		log.Info("CertificateRequest is Ready. Ignoring.")
		return ctrl.Result{}, nil
	}
	// Ignore CertificateRequest if it is already Failed
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	}) {
		log.Info("CertificateRequest is Failed. Ignoring.")
		return ctrl.Result{}, nil
	}
	// Ignore CertificateRequest if it already has a Denied Ready Reason
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonDenied,
	}) {
		log.Info("CertificateRequest already has a Ready condition with Denied Reason. Ignoring.")
		return ctrl.Result{}, nil
	}

	if r.CheckApprovedCondition {
		// If CertificateRequest has not been approved, exit early.
		if !cmutil.CertificateRequestIsApproved(&certificateRequest) {
			log.Info("CertificateRequest has not been approved yet. Ignoring.")
			return ctrl.Result{}, nil
		}
	}

	// report gives feedback by updating the Ready Condition of the Certificate Request.
	// For added visibility we also log a message and create a Kubernetes Event.
	report := func(reason, message string, failed bool, err error) {
		status := cmmeta.ConditionFalse
		if reason == cmapi.CertificateRequestReasonIssued {
			status = cmmeta.ConditionTrue
		}
		eventType := corev1.EventTypeNormal
		if err != nil {
			log.Error(err, message)
			eventType = corev1.EventTypeWarning
			message = fmt.Sprintf("%s: %v", message, err)
		} else {
			log.Info(message)
		}
		r.recorder.Event(
			&certificateRequest,
			eventType,
			essendixcissuerapi.EventReasonCertificateRequestReconciler,
			message,
		)
		if failed {
			cmutil.SetCertificateRequestCondition(
				&certificateRequest,
				cmapi.CertificateRequestReasonFailed,
				status,
				reason,
				message,
			)
		} else {
			cmutil.SetCertificateRequestCondition(
				&certificateRequest,
				cmapi.CertificateRequestConditionReady,
				status,
				reason,
				message,
			)

		}
	}

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			if strings.Contains(err.Error(), errSignerRefused.Error()) {
				report(cmapi.CertificateRequestReasonPending, "Temporary error. Retrying", false, err)
			}
		}
		if updateErr := r.Status().Update(ctx, &certificateRequest); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	// If CertificateRequest has been denied, mark the CertificateRequest as
	// Ready=Denied and set FailureTime if not already.
	if cmutil.CertificateRequestIsDenied(&certificateRequest) {
		log.Info("CertificateRequest has been denied yet. Marking as failed.")

		if certificateRequest.Status.FailureTime == nil {
			nowTime := metav1.NewTime(r.Clock.Now())
			certificateRequest.Status.FailureTime = &nowTime
		}

		message := "The CertificateRequest was denied by an approval controller"
		report(cmapi.CertificateRequestReasonDenied, message, false, nil)
		return ctrl.Result{}, nil
	}

	// Add a Ready condition if one does not already exist
	if ready := cmutil.GetCertificateRequestCondition(&certificateRequest, cmapi.CertificateRequestConditionReady); ready == nil {
		report(cmapi.CertificateRequestReasonPending, "Initialising Ready condition", false, nil)
		return ctrl.Result{}, nil
	}

	// Ignore but log an error if the issuerRef.Kind is unrecognised
	issuerGVK := essendixcissuerapi.GroupVersion.WithKind(certificateRequest.Spec.IssuerRef.Kind)
	issuerRO, err := r.Scheme.New(issuerGVK)
	if err != nil {
		report(cmapi.CertificateRequestReasonFailed, "Unrecognised kind. Ignoring", false, fmt.Errorf("%w: %v", errIssuerRef, false))
		return ctrl.Result{}, nil
	}
	issuer := issuerRO.(client.Object)
	// Create a Namespaced name for Issuer and a non-Namespaced name for ClusterIssuer
	issuerName := types.NamespacedName{
		Name: certificateRequest.Spec.IssuerRef.Name,
	}
	var secretNamespace string
	switch t := issuer.(type) {
	case *essendixcissuerapi.Issuer:
		issuerName.Namespace = certificateRequest.Namespace
		secretNamespace = certificateRequest.Namespace
		log = log.WithValues("issuer", issuerName)
	case *essendixcissuerapi.ClusterIssuer:
		secretNamespace = r.ClusterResourceNamespace
		log = log.WithValues("clusterissuer", issuerName)
	default:
		report(cmapi.CertificateRequestReasonFailed, "The issuerRef referred to a registered Kind which is not yet handled. Ignoring", false, fmt.Errorf("unexpected issuer type: %v", t))
		return ctrl.Result{}, nil
	}

	// Get the Issuer or ClusterIssuer
	if err := r.Get(ctx, issuerName, issuer); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errGetIssuer, err)
	}

	issuerSpec, issuerStatus, err := issuerutil.GetSpecAndStatus(issuer)
	if err != nil {
		report(cmapi.CertificateRequestReasonFailed, "Unable to get the IssuerStatus. Ignoring", false, err)
		return ctrl.Result{}, nil
	}

	if !issuerutil.IsReady(issuerStatus) {
		return ctrl.Result{}, errIssuerNotReady
	}

	secretName := types.NamespacedName{
		Name:      issuerSpec.AuthSecretName,
		Namespace: secretNamespace,
	}

	var secret corev1.Secret
	if err := r.Get(ctx, secretName, &secret); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, secretName, err)
	}

	log.Info("Signing certificate request evaluation", "issuer", issuerSpec.ProfileName, "subscriber", issuerSpec.SubscriberName)
	essendisigner, err := r.SignerBuilder(ctx, issuerSpec, r.AuthRealm, secret.Data)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerBuilder, err)
	}

	token, err := essendisigner.GetRefreshToken()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerBuilder, err)
	}

	statusEndpointUrl := ""
	resourceUrl := ""

	if issuerutil.IsSigned(&certificateRequest.Status) {
		issuedStatus := issuerutil.GetSignedCondition(&certificateRequest.Status)
		resourceUrl = strings.TrimSpace(strings.SplitN(issuedStatus.Message, ":", 2)[1])
		// log.Info("Certificate request already issued by CA", "instance", issuerSpec.URL, "resourceUrl", resourceUrl)
	} else {
		if issuerutil.IsSubmitted(&certificateRequest.Status) {
			submittedStatus := issuerutil.GetSubmittedCondition(&certificateRequest.Status)
			statusEndpointUrl = strings.TrimSpace(strings.SplitN(submittedStatus.Message, ":", 2)[1])
			log.Info("Certificate request already submitted", "instance", issuerSpec.URL, "statusEndpointUrl", statusEndpointUrl)
		} else {
			log.Info("Ready to send the singing request", "instance", issuerSpec.URL, "statusEndpointUrl", statusEndpointUrl)
			statusEndpointUrl, err := essendisigner.SubmitCertificateRequest(token, certificateRequest.Spec.Request)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerBuilder, err)
			}
			log.Info(essendixcissuerapi.IssuerConditionStatusSubmitted, "instance", issuerSpec.URL, "statusEndpointUrl", statusEndpointUrl)
			report(cmapi.CertificateRequestReasonPending, essendixcissuerapi.IssuerConditionStatusSubmitted+", status: "+statusEndpointUrl, false, nil)
			return ctrl.Result{RequeueAfter: defaultTaskCheckInterval}, nil
		}

		resourceUrl, taskStatus, err := essendisigner.RequestTaskStatus(token, statusEndpointUrl)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerBuilder, err)
		}
		if resourceUrl == "" {
			if taskStatus == essendixcissuerapi.TaskStatusProcessing && !issuerutil.IsProcessing(&certificateRequest.Status) {
				log.Info("Certificate request submitted, retry...", "instance", issuerSpec.URL, "statusEndpointUrl", statusEndpointUrl)
				report(cmapi.CertificateRequestReasonPending, essendixcissuerapi.IssuerConditionStatusProcessing+", resource: "+statusEndpointUrl, false, nil)
				return ctrl.Result{RequeueAfter: defaultTaskCheckInterval}, nil
			}
			if taskStatus == essendixcissuerapi.TaskStatusApproved && !issuerutil.IsApproved(&certificateRequest.Status) {
				log.Info("Certificate request approved, retry...", "instance", issuerSpec.URL, "statusEndpointUrl", statusEndpointUrl)
				report(cmapi.CertificateRequestReasonPending, essendixcissuerapi.IssuerConditionStatusApproved+", resource: "+statusEndpointUrl, false, nil)
				return ctrl.Result{RequeueAfter: defaultTaskCheckInterval}, nil
			}
			if taskStatus == essendixcissuerapi.TaskStatusDeclined {
				log.Info("Certificate request declined", "instance", issuerSpec.URL, "statusEndpointUrl", statusEndpointUrl)
				report(cmapi.CertificateRequestReasonFailed, "Request declined", false, nil)
				return ctrl.Result{}, nil
			}
			if taskStatus == essendixcissuerapi.TaskStatusCanceled {
				log.Info("Certificate request cancelled", "instance", issuerSpec.URL, "statusEndpointUrl", statusEndpointUrl)
				report(cmapi.CertificateRequestReasonFailed, "Request cancelled", false, nil)
				return ctrl.Result{}, nil
			}
			if taskStatus == essendixcissuerapi.TaskStatusFailed {
				log.Info("Certificate request failed in review", "instance", issuerSpec.URL, "statusEndpointUrl", statusEndpointUrl)
				report(cmapi.CertificateRequestReasonFailed, "Failed in review", false, nil)
				return ctrl.Result{}, nil
			}
			//log.Info("Certificate request still pending, retry...", "instance", issuerSpec.URL, "resourceUrl", statusEndpointUrl)
			return ctrl.Result{RequeueAfter: defaultTaskCheckInterval}, nil
		}
		log.Info("Certificate request signed by CA", "instance", issuerSpec.URL, "resourceUrl", resourceUrl)
		report(cmapi.CertificateRequestReasonPending, essendixcissuerapi.IssuerConditionStatusSigned+", resource: "+resourceUrl, false, nil)
		return ctrl.Result{}, nil
	}

	// Get the certificate
	signed, err := essendisigner.FetchCertificate(token, resourceUrl)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerBuilder, err)
	}
	certificateRequest.Status.Certificate = signed
	report(cmapi.CertificateRequestReasonIssued, "Signed", false, nil)

	return ctrl.Result{}, nil
}

func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recorder = mgr.GetEventRecorderFor(essendixcissuerapi.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
