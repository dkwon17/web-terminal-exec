//
// Copyright (c) 2019-2025 Red Hat, Inc.
// This program and the accompanying materials are made
// available under the terms of the Eclipse Public License 2.0
// which is available at https://www.eclipse.org/legal/epl-2.0/
//
// SPDX-License-Identifier: EPL-2.0
//
// Contributors:
//   Red Hat, Inc. - initial API and implementation

package tlssetup

import (
	"context"
	"crypto/tls"

	"github.com/sirupsen/logrus"
	configv1 "github.com/openshift/api/config/v1"
	ostls "github.com/openshift/controller-runtime-common/pkg/tls"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ShouldHonorClusterTLSProfile returns true when tlsAdherence requires strict adherence
func ShouldHonorClusterTLSProfile(adherence configv1.TLSAdherencePolicy) bool {
	switch adherence {
	case "", configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly:
		return false
	default:
		// StrictAllComponents or unknown future value → honor the profile
		return true
	}
}

// BuildClusterTLSConfig fetches TLS settings from the OpenShift APIServer and builds tls.Config.
// Returns nil on non-OpenShift, fetch failure, or when adherence policy doesn't require strict adherence.
// Falls back to Go TLS defaults (nil) on any error.
func BuildClusterTLSConfig(ctx context.Context) *tls.Config {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		logrus.WithError(err).Info("Not running in cluster; using Go default TLS configuration")
		return nil
	}

	// Create scheme with OpenShift types registered
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = configv1.AddToScheme(scheme)

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		logrus.WithError(err).Error("Failed to create Kubernetes client; using Go default TLS configuration")
		return nil
	}

	profile, err := ostls.FetchAPIServerTLSProfile(ctx, k8sClient)
	if err != nil {
		logrus.WithError(err).Info("Failed to fetch TLS profile from APIServer; using Go default TLS configuration")
		return nil
	}

	adherence, err := ostls.FetchAPIServerTLSAdherencePolicy(ctx, k8sClient)
	if err != nil {
		logrus.WithError(err).Error("Failed to fetch TLS adherence policy; using Go default TLS configuration")
		return nil
	}

	if !ShouldHonorClusterTLSProfile(adherence) {
		logrus.WithField("policy", adherence).Info("TLS adherence policy does not require strict adherence; using Go default TLS configuration")
		return nil
	}

	// Build tls.Config from cluster profile
	tlsConfig := &tls.Config{}
	tlsConfigFn, unsupported := ostls.NewTLSConfigFromProfile(profile)
	if len(unsupported) > 0 {
		logrus.WithField("unsupportedCiphers", unsupported).Info("TLS profile contains ciphers unsupported by Go; they will be ignored")
	}
	tlsConfigFn(tlsConfig)

	logrus.WithFields(logrus.Fields{
		"minTLSVersion":   profile.MinTLSVersion,
		"cipherCount":     len(profile.Ciphers),
		"adherencePolicy": adherence,
	}).Info("Applying cluster TLS profile to HTTPS server")

	return tlsConfig
}
