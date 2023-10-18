// Copyright 2023 The Inspektor Gadget authors
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

package instancemanager

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	runTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type gadgetState int

const (
	stateRunning = iota
	statePaused
	stateError
)

type GadgetInstance struct {
	request         *api.GadgetRunRequest
	mu              sync.Mutex
	eventBuffer     [][]byte
	eventBufferOffs int
	eventOverflow   bool
	results         runtime.CombinedGadgetResult
	gadgetCtx       *gadgetcontext.GadgetContext
	clients         map[*GadgetInstanceClient]struct{}
	cancel          func()
	state           gadgetState
	error           error
}

func (p *GadgetInstance) AddClient(client api.GadgetManager_AttachToGadgetInstanceServer) {
	log.Debugf("adding client")
	p.mu.Lock()
	defer p.mu.Unlock()
	cl := NewGadgetInstanceClient(client)
	p.clients[cl] = struct{}{}
	// TODO: Replay
	go func() {
		cl.Run()
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.clients, cl)
	}()
}

func (p *GadgetInstance) RunGadget(
	ctx context.Context,
	runtime runtime.Runtime,
	logger logger.Logger,
	request *api.GadgetRunRequest,
) error {
	gadgetDesc := gadgetregistry.Get(request.GadgetCategory, request.GadgetName)
	if gadgetDesc == nil {
		return fmt.Errorf("gadget not found: %s/%s", request.GadgetCategory, request.GadgetName)
	}

	// Initialize Operators
	err := operators.GetAll().Init(operators.GlobalParamsCollection())
	if err != nil {
		return fmt.Errorf("initialize operators: %w", err)
	}

	ops := operators.GetOperatorsForGadget(gadgetDesc)

	parser := gadgetDesc.Parser()

	operatorParams := ops.ParamCollection()
	runtimeParams := runtime.ParamDescs().ToParams()
	gadgetParamDescs := gadgetDesc.ParamDescs()

	gType := gadgetDesc.Type()
	// TODO: do we need to update gType before calling this?
	gadgetParamDescs.Add(gadgets.GadgetParams(gadgetDesc, gType, parser)...)
	gadgetParams := gadgetParamDescs.ToParams()

	err = gadgets.ParamsFromMap(request.Params, gadgetParams, runtimeParams, operatorParams)
	if err != nil {
		return fmt.Errorf("setting parameters: %w", err)
	}

	var gadgetInfo *runTypes.GadgetInfo

	if c, ok := gadgetDesc.(runTypes.RunGadgetDesc); ok {
		gadgetInfo, err = runtime.GetGadgetInfo(ctx, gadgetDesc, gadgetParams, request.Args)
		if err != nil {
			return fmt.Errorf("getting gadget info: %w", err)
		}
		parser, err = c.CustomParser(gadgetInfo)
		if err != nil {
			return fmt.Errorf("calling custom parser: %w", err)
		}

		// Update gadget parameters to take ebpf params into consideration
		for _, p := range gadgetInfo.GadgetMetadata.EBPFParams {
			p := p
			gadgetParamDescs.Add(&p.ParamDesc)
		}
		gadgetParams = gadgetParamDescs.ToParams()
		err = gadgetParams.CopyFromMap(request.Params, "")
		if err != nil {
			return fmt.Errorf("setting parameters: %w", err)
		}

	}

	if parser != nil {
		outputDone := make(chan bool)
		defer func() {
			outputDone <- true
		}()

		parser.SetLogCallback(logger.Logf)
		parser.SetEventCallback(func(ev any) {
			data, _ := json.Marshal(ev)

			p.mu.Lock()
			p.eventBuffer[p.eventBufferOffs] = data
			p.eventBufferOffs = (p.eventBufferOffs + 1) % len(p.eventBuffer)
			if p.eventBufferOffs == 0 {
				p.eventOverflow = true
			}
			for client := range p.clients {
				// This doesn't block
				client.SendPayload(data)
			}
			p.mu.Unlock()
		})
	}

	// Assign a unique ID - this will be used in the future
	runID := uuid.New().String()

	// Create new Gadget Context
	gadgetCtx := gadgetcontext.New(
		ctx,
		runID,
		runtime,
		runtimeParams,
		gadgetDesc,
		gadgetParams,
		request.Args,
		operatorParams,
		parser,
		logger,
		time.Duration(request.Timeout),
		gadgetInfo,
	)
	defer gadgetCtx.Cancel()

	p.gadgetCtx = gadgetCtx

	// Hand over to runtime
	results, err := runtime.RunGadget(gadgetCtx)
	if err != nil {
		return fmt.Errorf("running gadget: %w", err)
	}

	// Send result, if any
	p.mu.Lock()
	p.results = results
	p.state = statePaused
	p.mu.Unlock()

	return nil
}