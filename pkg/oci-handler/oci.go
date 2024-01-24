// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ocihandler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	validateMetadataParam = "validate-metadata"
	authfileParam         = "authfile"
	insecureParam         = "insecure"
	pullParam             = "pull"
	pullSecret            = "pull-secret"
)

// ociHandler bridges our legacy operator system with the image based gadgets
// once we remove the legacy gadgets, this operator should be called directly as if it
// were the gadget
type ociHandler struct{}

func (o *ociHandler) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		// Hardcoded for now
		{
			Key:          authfileParam,
			Title:        "Auth file",
			Description:  "Path of the authentication file. This overrides the REGISTRY_AUTH_FILE environment variable",
			DefaultValue: oci.DefaultAuthFile,
			TypeHint:     params.TypeString,
		},
		{
			Key:          validateMetadataParam,
			Title:        "Validate metadata",
			Description:  "Validate the gadget metadata before running the gadget",
			DefaultValue: "true",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          insecureParam,
			Title:        "Insecure connection",
			Description:  "Allow connections to HTTP only registries",
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          pullParam,
			Title:        "Pull policy",
			Description:  "Specify when the gadget image should be pulled",
			DefaultValue: oci.PullImageMissing,
			PossibleValues: []string{
				oci.PullImageAlways,
				oci.PullImageMissing,
				oci.PullImageNever,
			},
			TypeHint: params.TypeString,
		},
		{
			Key:         pullSecret,
			Title:       "Pull secret",
			Description: "Secret to use when pulling the gadget image",
			TypeHint:    params.TypeString,
		},
	}
}

func getPullSecret(pullSecretString string, gadgetNamespace string) ([]byte, error) {
	k8sClient, err := k8sutil.NewClientset("")
	if err != nil {
		return nil, fmt.Errorf("creating new k8s clientset: %w", err)
	}
	gps, err := k8sClient.CoreV1().Secrets(gadgetNamespace).Get(context.TODO(), pullSecretString, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting secret %q: %w", pullSecretString, err)
	}
	if gps.Type != corev1.SecretTypeDockerConfigJson {
		return nil, fmt.Errorf("secret %q is not of type %q", pullSecretString, corev1.SecretTypeDockerConfigJson)
	}
	return gps.Data[corev1.DockerConfigJsonKey], nil
}

func (o *ociHandler) Instantiate(gadgetCtx operators.GadgetContext, paramValueMap map[string]string) (*OciHandlerInstance, error) {
	if len(gadgetCtx.ImageName()) == 0 {
		return nil, fmt.Errorf("imageName empty")
	}

	ociParams := o.ParamDescs().ToParams()
	err := ociParams.CopyFromMap(paramValueMap, "oci.")
	if err != nil {
		return nil, fmt.Errorf("validating oci params: %w", err)
	}

	// gadgetParams in the paramValueMap will be prefixed with "gadget.", let's extract them here to forward them to the
	// image operators
	gadgetParams := make(map[string]string)
	for k, v := range paramValueMap {
		if strings.HasPrefix(k, "gadget.") {
			gadgetParams[strings.TrimPrefix(k, "gadget.")] = v
		}
	}

	// TODO: move to a place without dependency on k8s
	pullSecretString := ociParams.Get(pullSecret).AsString()
	var secretBytes []byte = nil
	if pullSecretString != "" {
		var err error
		// TODO: Namespace is still hardcoded
		secretBytes, err = getPullSecret(pullSecretString, "gadget")
		if err != nil {
			return nil, err
		}
	}

	authOpts := &oci.AuthOptions{
		AuthFile:    ociParams.Get(authfileParam).AsString(),
		SecretBytes: secretBytes,
		Insecure:    ociParams.Get(insecureParam).AsBool(),
	}

	// Make sure the image is available, either through pulling or by just accessing a local copy
	// TODO: add security constraints (e.g. don't allow pulling - add GlobalParams for that)
	err = oci.EnsureImage(gadgetCtx.Context(), gadgetCtx.ImageName(), authOpts, ociParams.Get(pullParam).AsString())
	if err != nil {
		return nil, fmt.Errorf("ensuring image: %w", err)
	}

	manifest, err := oci.GetManifestForHost(gadgetCtx.Context(), gadgetCtx.ImageName())
	if err != nil {
		return nil, fmt.Errorf("getting manifest: %w", err)
	}

	logger := gadgetCtx.Logger()

	r, err := oci.GetContentFromDescriptor(gadgetCtx.Context(), manifest.Config)
	if err != nil {
		return nil, fmt.Errorf("getting metadata: %w", err)
	}
	metadata, _ := io.ReadAll(r)
	r.Close()

	// Store metadata for serialization
	gadgetCtx.SetMetadata(metadata)

	viper := viper.New()
	viper.SetConfigType("yaml")
	err = viper.ReadConfig(bytes.NewReader(metadata))

	if err != nil {
		return nil, fmt.Errorf("unmarshalling metadata: %w", err)
	}

	gadgetCtx.SetVar("config", viper)

	instance := &OciHandlerInstance{
		gadgetCtx:     gadgetCtx,
		paramValueMap: paramValueMap,
	}

	for _, layer := range manifest.Layers {
		logger.Debugf("layer > %+v", layer)
		op, ok := operators.GetImageOperatorForMediaType(layer.MediaType)
		if !ok {
			continue
		}
		logger.Debugf("found image op %q", op.Name())
		opInst, err := op.InstantiateImageOperator(gadgetCtx, layer, nil, gadgetParams)
		if err != nil {
			logger.Errorf("instantiating operator %q: %v", op.Name(), err)
		}
		if opInst == nil {
			logger.Debugf("> skipped %s", op.Name())
			continue
		}
		instance.imageOperatorInstances = append(instance.imageOperatorInstances, opInst)
	}

	for _, op := range operators.GetDataOperators() {
		logger.Debugf("found data op %q", op.Name())

		// Lazily initialize operator
		// TODO: global params should be filled out from a config file or such; maybe it's a better idea not to
		// lazily initialize operators at all, but just hand over the config. The "lazy" stuff could then be done
		// if the operator is instantiated and needs to do work
		err := op.Init(op.GlobalParamDescs().ToParams())
		if err != nil {
			return nil, fmt.Errorf("initializing operator %q: %w", op.Name(), err)
		}

		opInst, err := op.InstantiateDataOperator(gadgetCtx)
		if err != nil {
			logger.Errorf("instantiating operator %q: %v", op.Name(), err)
		}
		if opInst == nil {
			logger.Debugf("> skipped %s", op.Name())
			continue
		}
		instance.dataOperatorInstances = append(instance.dataOperatorInstances, opInst)
	}

	// Sort dataOperators based on their priority
	sort.Slice(instance.dataOperatorInstances, func(i, j int) bool {
		return instance.dataOperatorInstances[i].Priority() < instance.dataOperatorInstances[j].Priority()
	})

	return instance, nil
}

func (o *OciHandlerInstance) ParamDescs() params.ParamDescs {
	return nil
}

func (o *OciHandlerInstance) Prepare() error {
	gadgetParams := make([]*api.Param, 0)
	for _, opInst := range o.imageOperatorInstances {
		err := opInst.Prepare(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("preparing operator %q: %v", opInst.Name(), err)
		}

		// Add gadget params
		for _, p := range opInst.GadgetParams() {
			p.Prefix = "gadget."
		}

		// After calling Params(), we can extract GadgetParams, so let's add them
		gadgetParams = append(gadgetParams, opInst.GadgetParams()...)
	}

	for _, opInst := range o.dataOperatorInstances {
		opParamPrefix := fmt.Sprintf("operator.%s.", opInst.Name())

		// Get and fill params
		params := opInst.ParamDescs(o.gadgetCtx).ToParams()

		err := params.CopyFromMap(o.paramValueMap, opParamPrefix)
		if err != nil {
			return fmt.Errorf("validating params for operator %q: %w", opInst.Name(), err)
		}

		err = opInst.Prepare(o.gadgetCtx, params)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("preparing operator %q: %v", opInst.Name(), err)
			continue
		}

		// Second pass params; this time the operator had the chance to prepare itself based on DataSources, etc.
		// this mainly is postponed to read default values that might differ from before; this second pass is
		// what is handed over to the remote end
		pd := opInst.ParamDescs(o.gadgetCtx)
		gadgetParams = append(gadgetParams, api.ParamDescsToParams(pd, opParamPrefix)...)
	}

	o.gadgetCtx.SetParams(gadgetParams)
	return nil
}

func (o *OciHandlerInstance) Start() error {
	// Run
	for _, opInst := range o.dataOperatorInstances {
		err := opInst.Start(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("starting operator %q: %v", opInst.Name(), err)
		}
	}
	for _, opInst := range o.imageOperatorInstances {
		err := opInst.Start(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("starting operator %q: %v", opInst.Name(), err)
		}
	}
	return nil
}

func (o *OciHandlerInstance) Stop() error {
	for _, opInst := range o.imageOperatorInstances {
		err := opInst.Stop(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("starting operator %q: %v", opInst.Name(), err)
		}
	}
	for _, opInst := range o.dataOperatorInstances {
		err := opInst.Stop(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("stopping operator %q: %v", opInst.Name(), err)
		}
	}
	return nil
}

type OciHandlerInstance struct {
	gadgetCtx              operators.GadgetContext
	imageOperatorInstances []operators.ImageOperatorInstance
	dataOperatorInstances  []operators.DataOperatorInstance
	paramValueMap          map[string]string
}

// OciHandler is a singleton of ociHandler
var OciHandler = &ociHandler{}
