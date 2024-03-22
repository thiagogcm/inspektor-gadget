// Copyright 2023-2024 The Inspektor Gadget authors
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

package datasource

import (
	"encoding/binary"
	"io"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

type Type uint32

const (
	TypeUndefined Type = iota
	TypeEvent
	TypeArray
	TypeMetrics
)

type Payload interface {
	Set(index uint32, data []byte)
	SetChunk(index uint32, offset uint32, size uint32, data []byte)
	Get(index uint32) []byte
	GetChunk(index uint32, offset uint32, size uint32) []byte
	TotalIndexes() uint32
}

type GadgetPayload interface {
	Raw() protoreflect.ProtoMessage
	Each(func(Payload) error) error
}

type GadgetPayloadEvent interface {
	GadgetPayload
	GetPayload() Payload
}

type GadgetPayloadArray interface {
	GadgetPayload
	New() Payload
	Add(...Payload)
	GetPayloadArray() []Payload
}

// DataFunc is the callback that will be called for Data emitted by a DataSource. Data has to be consumed
// synchronously and may not be accessed after returning - make a copy if you need to hold on to Data.
type DataFunc func(DataSource, GadgetPayload) error

// DataSource is an interface that represents a data source of a gadget. Usually, it represents a map in eBPF and some
// tooling around handling it in Go. An eBPF program can have multiple DataSources, each one representing a different
// map.
type DataSource interface {
	// Name returns the name of the data source
	Name() string

	// Type returns the type of the data source
	Type() Type

	// AddStaticFields adds fields inside a container that has a fixed size; use it to directly map for example
	// eBPF structs
	AddStaticFields(totalSize uint32, fields []Field) (FieldAccessor, error)

	// AddField adds a field as a new payload
	AddField(fieldName string, options ...FieldOption) (FieldAccessor, error)
	GetField(fieldName string) FieldAccessor
	GetFieldsWithTag(tag ...string) []FieldAccessor

	// NewGadgetPayloadEvent builds a new GadgetPayloadEvent
	NewGadgetPayloadEvent() GadgetPayloadEvent
	NewGadgetPayloadArray() GadgetPayloadArray

	// EmitAndRelease sends data through the operator chain and releases it afterward;
	// Data may not be used after calling this. This should only be used in the running phase of the gadget, not
	// in the initialization phase.
	EmitAndRelease(GadgetPayload) error

	// Release releases the memory of Data; Data may not be used after calling this
	Release(GadgetPayload)

	// ReportLostData reports a number of lost data cases
	ReportLostData(lostSampleCount uint64)

	// Dump dumps the content of Data to a writer for debugging purposes
	Dump(GadgetPayload, io.Writer)

	// Subscribe makes sure that events emitted from this DataSource are passed to DataFunc; subscribers will be
	// sorted by priority and handed over data in that order (lower numbers = earlier). Subscriptions to
	// DataSources should only happen in the initialization phase. Data sent to dataFn has to be consumed synchronously
	// and must not be accessed after returning.
	Subscribe(dataFn DataFunc, priority int)

	Parser() (parser.Parser, error)

	Fields() []*api.Field

	Accessors(rootOnly bool) []FieldAccessor

	IsRequested() bool

	// ByteOrder returns a binary accessor using the byte order of the creator of the DataSource
	ByteOrder() binary.ByteOrder

	// SetVisibleFields specifies exactly which fields are set to visible/hidden; field names can be prefixed with
	// +/- to add or remove the field from the output - if all fields are prefixed, the default visible fields will be
	// honored, otherwise only the fields specified will be considered. If fields is nil, the default will be used - if
	// fields is empty, no field will be returned.
	SetVisibleFields(fields []string)

	AddAnnotation(key, value string)
	AddTag(tag string)

	Annotations() map[string]string
	Tags() []string
}
