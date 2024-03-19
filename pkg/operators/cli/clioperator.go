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

package clioperator

import (
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	// Priority is set to a high value, since this operator is used as sink and so all changes to DataSources need
	// to have happened before the operator becomes active
	Priority = 10000

	ParamFields = "fields"
	ParamMode   = "output-mode"

	ModeJSON    = "json"
	ModeColumns = "columns"
)

type cliOperator struct{}

func (o *cliOperator) Name() string {
	return "cliOperator"
}

func (o *cliOperator) Init(params *params.Params) error {
	return nil
}

func (o *cliOperator) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (o *cliOperator) InstantiateDataOperator(ctx operators.GadgetContext) (operators.DataOperatorInstance, error) {
	return &cliOperatorInstance{
		outputDefaults: make(map[string]string),
		headers:        make(map[string]string),
		mode:           ModeJSON,
	}, nil
}

type cliOperatorInstance struct {
	outputDefaults map[string]string
	headers        map[string]string
	mode           string
}

func (c *cliOperatorInstance) Name() string {
	return "cliOperatorInstance"
}

func (c *cliOperatorInstance) Priority() int {
	return Priority
}

func (c *cliOperatorInstance) ParamDescs(gadgetCtx operators.GadgetContext) params.ParamDescs {
	// output format should be:
	// --fields datasource:comma,separated,fields
	fields := &params.ParamDesc{
		Key:          ParamFields,
		DefaultValue: "value",
		Description:  "",
	}

	// Fetch defaults
	var str strings.Builder
	for _, v := range c.outputDefaults {
		str.WriteString(v)
		str.WriteByte(';')
	}

	mode := &params.ParamDesc{
		Key:            ParamMode,
		DefaultValue:   ModeJSON,
		Description:    "output mode",
		PossibleValues: []string{ModeJSON, ModeColumns},
	}

	return params.ParamDescs{fields, mode}
}

func (c *cliOperatorInstance) Prepare(gadgetCtx operators.GadgetContext, params *params.Params) error {
	for _, ds := range gadgetCtx.GetDataSources() {
		gadgetCtx.Logger().Debugf("subscribing to %s", ds.Name())

		p, err := ds.Parser()
		if err != nil {
			gadgetCtx.Logger().Debugf("failed to get parser: %v", err)
			continue
		}

		defCols := p.GetDefaultColumns()
		gadgetCtx.Logger().Debugf("default fields: %s", defCols)
		formatter := p.GetTextColumnsFormatter()

		// Build output default
		var flag strings.Builder
		flag.WriteString(ds.Name())
		flag.WriteString(":")
		flag.WriteString(strings.Join(defCols, ","))
		c.outputDefaults[ds.Name()] = flag.String()

		// xformatter := json.NewFormatter[datasource.DataTuple](p.GetColumns().(columns.Columns[datasource.DataTuple]).GetColumnMap())
		// p.SetEventCallback(xformatter.FormatEntries)

		if c.mode == ModeColumns {
			c.headers[ds.Name()] = fmt.Sprintf("%s\n", formatter.FormatHeader())
		}

		formatter.SetEventCallback(func(s string) {
			fmt.Print(s)
			fmt.Print("\n")
		})

		p.SetEventCallback(formatter.EventHandlerFunc())
		handler, ok := p.EventHandlerFunc().(func(data *datasource.DataTuple))
		if !ok {
			gadgetCtx.Logger().Warnf("invalid data format: expected func(data *datasource.DataTuple), got %T",
				p.EventHandlerFunc())
			continue
		}

		jsonFormatter := json.New(ds)

		ds.Subscribe(func(ds datasource.DataSource, gp datasource.GadgetPayload) error {
			return gp.Each(func(p datasource.Payload) error {
				if false {
					handler(datasource.NewDataTuple(ds, p))
				}
				fmt.Print(string(jsonFormatter.Marshal(p)))
				fmt.Print("\n")
				return nil
			})
		}, Priority)
	}

	return nil
}

func (c *cliOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	if c.mode == ModeColumns {
		for _, hdr := range c.headers {
			fmt.Print(hdr)
		}
	}
	return nil
}

func (c *cliOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

// Register registers CLIOperator as operator; this should only happen for applications with local output
func Register() {
	operators.RegisterDataOperator(&cliOperator{})
}
