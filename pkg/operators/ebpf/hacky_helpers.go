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

package ebpfoperator

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"
	_ "unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfhelpers"
)

// fillParamDefaults will fill out i.Params' default values; it is quite
// hacky since cilium/ebpf doesn't export the necessary interfaces to
// easily access those values
func (i *ebpfInstance) fillParamDefaults() error {
	spec := i.collectionSpec
	for name, spec := range spec.Maps {
		if !strings.HasPrefix(name, ".rodata") {
			continue
		}
		b, ds, err := dataSection(spec)
		if errors.Is(err, errMapNoBTFValue) {
			continue
		}
		if err != nil {
			return fmt.Errorf("map %s: %w", name, err)
		}

		for _, v := range ds.Vars {
			vname := v.Type.TypeName()

			param, ok := i.params[vname]
			if !ok {
				continue
			}

			if int(v.Offset+v.Size) > len(b) {
				continue
			}

			btfVar, ok := v.Type.(*btf.Var)
			if !ok {
				continue
			}

			btfConst, ok := btfVar.Type.(*btf.Const)
			if !ok {
				continue
			}

			btfVolatile, ok := btfConst.Type.(*btf.Volatile)
			if !ok {
				continue
			}

			vtype := btfVolatile.Type

			if typedef, ok := vtype.(*btf.Typedef); ok {
				vtype = btfhelpers.GetUnderlyingType(typedef)
			}

			bytes := b[v.Offset : v.Offset+v.Size]

			var defaultValue string

			switch t := vtype.(type) {
			case *btf.Int:
				if t.Encoding&btf.Signed != 0 {
					switch t.Size {
					case 1:
						defaultValue = fmt.Sprintf("%d", int8(bytes[0]))
					case 2:
						defaultValue = fmt.Sprintf("%d", *(*int16)(unsafe.Pointer(&bytes[0])))
					case 4:
						defaultValue = fmt.Sprintf("%d", *(*int32)(unsafe.Pointer(&bytes[0])))
					case 8:
						defaultValue = fmt.Sprintf("%d", *(*int64)(unsafe.Pointer(&bytes[0])))
					}
				} else {
					switch t.Size {
					case 1:
						defaultValue = fmt.Sprintf("%d", bytes[0])
					case 2:
						defaultValue = fmt.Sprintf("%d", *(*uint16)(unsafe.Pointer(&bytes[0])))
					case 4:
						defaultValue = fmt.Sprintf("%d", *(*uint32)(unsafe.Pointer(&bytes[0])))
					case 8:
						defaultValue = fmt.Sprintf("%d", *(*uint64)(unsafe.Pointer(&bytes[0])))
					}
				}
				if t.Encoding&btf.Bool != 0 {
					if defaultValue == "0" {
						defaultValue = "false"
					} else {
						defaultValue = "true"
					}
				}
			}

			i.gadgetCtx.Logger().Debugf("default value for param %q set to %q (%.2X), type was %T", vname, defaultValue, bytes, vtype)

			param.DefaultValue = defaultValue
		}
	}
	return nil
}

//go:linkname dataSection github.com/cilium/ebpf.(*MapSpec).dataSection
func dataSection(*ebpf.MapSpec) ([]byte, *btf.Datasec, error)

//go:linkname errMapNoBTFValue github.com/cilium/ebpf.errMapNoBTFValue
var errMapNoBTFValue error
