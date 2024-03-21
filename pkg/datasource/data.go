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

package datasource

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

type gPayloadEvent api.GadgetPayloadEvent

func (e *gPayloadEvent) Raw() protoreflect.ProtoMessage {
	return (*api.GadgetPayloadEvent)(e)
}

func (e *gPayloadEvent) Each(fn func(Payload) error) error {
	return fn((*payload)(e.Payload))
}

func (e *gPayloadEvent) GetPayload() Payload {
	return (*payload)(e.Payload)
}

type gPayloadArray struct {
	*api.GadgetPayloadArray

	// payloadSize is the size of each payload array. It is used to pre-allocate
	// the payload array in the NewPayload method.
	payloadSize uint32
}

func (a *gPayloadArray) Raw() protoreflect.ProtoMessage {
	return (*api.GadgetPayloadArray)(a.GadgetPayloadArray)
}

func (a *gPayloadArray) Each(fn func(Payload) error) error {
	for _, p := range a.Payloads {
		if err := fn((*payload)(p)); err != nil {
			return err
		}
	}
	return nil
}

func (a *gPayloadArray) New() Payload {
	p := &api.Payload{
		Data: make([][]byte, a.payloadSize),
	}
	for i := range p.Data {
		p.Data[i] = make([]byte, 0)
	}
	return (*payload)(p)
}

func (a *gPayloadArray) Add(p Payload) {
	a.Payloads = append(a.Payloads, (*api.Payload)(p.(*payload)))
}

func (a *gPayloadArray) GetPayloadArray() []Payload {
	res := make([]Payload, 0, len(a.Payloads))
	for _, p := range a.Payloads {
		res = append(res, (*payload)(p))
	}
	return res
}

type payload api.Payload

func (p *payload) Set(index uint32, data []byte) {
	if index >= uint32(len(p.Data)) {
		return
	}
	p.Data[index] = data
}

func (p *payload) SetChunk(index uint32, offset uint32, size uint32, data []byte) {
	if index >= uint32(len(p.Data)) {
		return
	}
	if offset+size > uint32(len(p.Data[index])) {
		return
	}
	copy(p.Data[index][offset:offset+size], data)
}

func (p *payload) Get(index uint32) []byte {
	if index >= uint32(len(p.Data)) {
		return nil
	}
	return p.Data[index]
}

func (p *payload) GetChunk(index uint32, offset uint32, size uint32) []byte {
	if index >= uint32(len(p.Data)) {
		return nil
	}
	if offset+size > uint32(len(p.Data[index])) {
		return nil
	}
	return p.Data[index][offset : offset+size]
}

func (p *payload) TotalIndexes() uint32 {
	return uint32(len(p.Data))
}

type field api.Field

func (f *field) ReflectType() reflect.Type {
	switch f.Kind {
	default:
		return nil
	case api.Kind_Int8:
		return reflect.TypeOf(int8(0))
	case api.Kind_Int16:
		return reflect.TypeOf(int16(0))
	case api.Kind_Int32:
		return reflect.TypeOf(int32(0))
	case api.Kind_Int64:
		return reflect.TypeOf(int64(0))
	case api.Kind_Uint8:
		return reflect.TypeOf(uint8(0))
	case api.Kind_Uint16:
		return reflect.TypeOf(uint16(0))
	case api.Kind_Uint32:
		return reflect.TypeOf(uint32(0))
	case api.Kind_Uint64:
		return reflect.TypeOf(uint64(0))
	case api.Kind_Float32:
		return reflect.TypeOf(float32(0))
	case api.Kind_Float64:
		return reflect.TypeOf(float64(0))
	case api.Kind_Bool:
		return reflect.TypeOf(false)
	}
}

type dataSource struct {
	name string
	id   uint32

	dType Type
	dPool sync.Pool

	// keeps information on registered fields
	fields   []*field
	fieldMap map[string]*field

	tags        []string
	annotations map[string]string

	payloadCount uint32

	requestedFields map[string]bool

	subscriptions []*subscription

	requested bool

	byteOrder binary.ByteOrder
	lock      sync.RWMutex

	logger logger.Logger
}

func newDataSource(t Type, name string, l logger.Logger) *dataSource {
	return &dataSource{
		name:            name,
		dType:           t,
		requestedFields: make(map[string]bool),
		fieldMap:        make(map[string]*field),
		byteOrder:       NativeEndian,
		tags:            make([]string, 0),
		annotations:     map[string]string{},
		logger:          l,
	}
}

func New(t Type, name string, l logger.Logger) DataSource {
	ds := newDataSource(t, name, l)
	ds.registerPool()
	return ds
}

func NewFromAPI(in *api.DataSource, l logger.Logger) (DataSource, error) {
	ds := newDataSource(Type(in.Type), in.Name, l)
	for _, f := range in.Fields {
		ds.fields = append(ds.fields, (*field)(f))
		ds.fieldMap[f.Name] = (*field)(f)
	}
	if in.Flags&api.DataSourceFlagsBigEndian != 0 {
		ds.byteOrder = binary.BigEndian
	} else {
		ds.byteOrder = binary.LittleEndian
	}
	ds.registerPool()
	// TODO: add more checks / validation
	return ds, nil
}

func (ds *dataSource) registerPool() {
	// switch ds.dType {
	// case TypeEvent:
	// 	ds.dPool.New = func() any {
	// 		gp := &gPayloadEvent{
	// 			Payload: &api.Payload{
	// 				Data: make([][]byte, ds.payloadCount),
	// 			},
	// 		}
	// 		for i := range gp.Payload.Data {
	// 			gp.Payload.Data[i] = make([]byte, 0)
	// 		}
	// 		return gp
	// 	}
	// case TypeArray:
	// 	ds.dPool.New = func() any {
	// 		// payloadSize will be used to pre-allocate the payload array in
	// 		// gPayloadArray.New().
	// 		return &gPayloadArray{
	// 			GadgetPayloadArray: &api.GadgetPayloadArray{
	// 				Payloads: make([]*api.Payload, 0),
	// 			},
	// 			payloadSize: ds.payloadCount,
	// 		}
	// 	}
	// }
}

func (ds *dataSource) Name() string {
	return ds.name
}

func (ds *dataSource) Type() Type {
	return ds.dType
}

func (ds *dataSource) NewGadgetPayloadEvent() GadgetPayloadEvent {
	if ds.dType != TypeEvent {
		return nil
	}
	// return ds.dPool.Get().(GadgetPayloadEvent) - panic: interface conversion: *api.GadgetPayloadEvent is not datasource.GadgetPayloadEvent: missing method Each
	// return ds.dPool.Get().(*gPayloadEvent) - panic: interface conversion: interface {} is *api.GadgetPayloadEvent, not *datasource.gPayloadEvent
	// api := ds.dPool.Get().(*api.GadgetPayloadEvent) return (*gPayloadEvent)(api) panic: interface conversion: interface {} is *datasource.gPayloadEvent, not *api.GadgetPayloadEvent
	// return ds.dPool.Get().(*gPayloadEvent)

	gp := &gPayloadEvent{
		Payload: &api.Payload{
			Data: make([][]byte, ds.payloadCount),
		},
	}
	for i := range gp.Payload.Data {
		gp.Payload.Data[i] = make([]byte, 0)
	}
	return gp
}

func (ds *dataSource) NewGadgetPayloadArray() GadgetPayloadArray {
	if ds.dType != TypeArray {
		return nil
	}
	//	return ds.dPool.Get().(GadgetPayloadArray)  - panic: interface conversion: *api.GadgetPayloadArray is not datasource.GadgetPayloadArray: missing method Add

	// payloadSize will be used to pre-allocate the payload array in
	// gPayloadArray.New().
	return &gPayloadArray{
		GadgetPayloadArray: &api.GadgetPayloadArray{
			Payloads: make([]*api.Payload, 0),
		},
		payloadSize: ds.payloadCount,
	}
}

func (ds *dataSource) ByteOrder() binary.ByteOrder {
	return ds.byteOrder
}

func resolveNames(id uint32, fields []*field, parentOffset uint32) (string, error) {
	if id >= uint32(len(fields)) {
		return "", errors.New("invalid parent id")
	}
	out := ""
	if FieldFlagHasParent.In(fields[id].Flags) {
		p, err := resolveNames(fields[id].Parent-parentOffset, fields, parentOffset)
		if err != nil {
			return "", errors.New("parent not found")
		}
		out = p + "."
	}
	out += fields[id].Name
	return out, nil
}

// AddStaticFields adds a statically sized container for fields to the payload and returns an accessor for the
// container; if you want to access individual fields, get them from the DataSource directly
func (ds *dataSource) AddStaticFields(size uint32, fields []Field) (FieldAccessor, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	idx := ds.payloadCount

	// temporary write to newFields to not write to ds.fields in case of errors
	var newFields []*field

	parentOffset := len(ds.fields)

	for _, f := range fields {
		if _, ok := ds.fieldMap[f.FieldName()]; ok {
			return nil, fmt.Errorf("field %q already exists", f.FieldName())
		}
		staticField, ok := f.(StaticField)
		fieldName := f.FieldName()
		if !ok {
			return nil, fmt.Errorf("field %q is not statically sized or does not implement StaticField", fieldName)
		}
		nf := &field{
			Name:         fieldName,
			Index:        uint32(len(ds.fields) + len(newFields)),
			PayloadIndex: idx,
			Flags:        FieldFlagStaticMember.Uint32(),
		}
		nf.Size = staticField.FieldSize()
		nf.Offs = staticField.FieldOffset()
		if nf.Offs+nf.Size > size {
			return nil, fmt.Errorf("field %q exceeds size of container (offs %d, size %d, container size %d)", nf.Name, nf.Offs, nf.Size, size)
		}
		if s, ok := f.(TypedField); ok {
			nf.Kind = s.FieldType()
		}
		if tagger, ok := f.(TaggedField); ok {
			nf.Tags = tagger.FieldTags()
		}
		if s, ok := f.(FlaggedField); ok {
			nf.Flags |= uint32(s.FieldFlags())
		}
		if s, ok := f.(ParentedField); ok {
			parent := s.FieldParent()
			if parent >= 0 {
				nf.Parent = uint32(parent + parentOffset)                          // TODO: validate?
				nf.Flags |= FieldFlagHasParent.Uint32() | FieldFlagHidden.Uint32() // default to hide subfields
			}
		}

		ds.logger.Debugf("new static field: name %s type %s PayloadIndex %d size %d offset %d\n",
			fieldName, nf.Kind, idx, nf.Size, nf.Offs)

		newFields = append(newFields, nf)
	}

	var err error
	for i, f := range newFields {
		f.FullName, err = resolveNames(uint32(i), newFields, uint32(parentOffset))
		if err != nil {
			return nil, fmt.Errorf("resolving full fieldnames: %w", err)
		}
	}

	ds.fields = append(ds.fields, newFields...)

	for _, f := range newFields {
		ds.fieldMap[f.Name] = f
	}

	ds.payloadCount++

	ds.logger.Debugf("new static fields: PayloadIndex %d size %d numFields %d\n", idx, size, len(newFields))

	return &fieldAccessor{ds: ds, f: &field{
		PayloadIndex: idx,
		Size:         size,
	}}, nil
}

func (ds *dataSource) AddField(name string, opts ...FieldOption) (FieldAccessor, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	if _, ok := ds.fieldMap[name]; ok {
		return nil, fmt.Errorf("field %q already exists", name)
	}

	nf := &field{
		Name:     name,
		FullName: name,
		Index:    uint32(len(ds.fields)),
		Kind:     api.Kind_Invalid,
	}
	for _, opt := range opts {
		opt(nf)
	}

	// Reserve new payload for non-empty fields
	if !FieldFlagEmpty.In(nf.Flags) {
		nf.PayloadIndex = ds.payloadCount
		ds.payloadCount++
	}

	ds.fields = append(ds.fields, nf)
	ds.fieldMap[nf.FullName] = nf

	ds.logger.Debugf("new dynamic field: name %s PayloadIndex %d size %d\n", name, nf.PayloadIndex, nf.Size)

	return &fieldAccessor{ds: ds, f: nf}, nil
}

func (ds *dataSource) GetField(name string) FieldAccessor {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	f, ok := ds.fieldMap[name]
	if !ok {
		return nil
	}
	return &fieldAccessor{ds: ds, f: f}
}

func (ds *dataSource) GetFieldsWithTag(tag ...string) []FieldAccessor {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	res := make([]FieldAccessor, 0)
	for _, f := range ds.fields {
		for _, t := range tag {
			if slices.Contains(f.Tags, t) {
				res = append(res, &fieldAccessor{ds: ds, f: f})
				break
			}
		}
	}
	return res
}

func (ds *dataSource) Subscribe(fn DataFunc, priority int) {
	if fn == nil {
		return
	}

	ds.lock.Lock()
	defer ds.lock.Unlock()

	ds.subscriptions = append(ds.subscriptions, &subscription{
		priority: priority,
		fn:       fn,
	})
	sort.SliceStable(ds.subscriptions, func(i, j int) bool {
		return ds.subscriptions[i].priority < ds.subscriptions[j].priority
	})
}

func (ds *dataSource) EmitAndRelease(gp GadgetPayload) error {
	// TODO(JOSE): It's not releasing the whole struct for the gPayloadArray
	defer ds.dPool.Put(gp.Raw())
	for _, sub := range ds.subscriptions {
		err := sub.fn(ds, gp)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ds *dataSource) Release(gp GadgetPayload) {
	ds.dPool.Put(gp.Raw())
}

func (ds *dataSource) ReportLostData(ctr uint64) {
	// TODO
}

func (ds *dataSource) IsRequestedField(fieldName string) bool {
	return true
	// ds.lock.RLock()
	// defer ds.lock.RUnlock()
	// return ds.requestedFields[fieldName]
}

func (ds *dataSource) Dump(gp GadgetPayload, wr io.Writer) {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	gp.Each(func(p Payload) error {
		for _, f := range ds.fields {
			if f.Offs+f.Size > uint32(len(p.Get(f.PayloadIndex))) {
				fmt.Fprintf(wr, "%s (%d): ! invalid size\n", f.Name, f.Size)
				continue
			}
			fmt.Fprintf(wr, "%s (%d) [%s]: ", f.Name, f.Size, strings.Join(f.Tags, " "))
			if f.Offs > 0 || f.Size > 0 {
				fmt.Fprintf(wr, "%v\n", p.GetChunk(f.PayloadIndex, f.Offs, f.Size))
			} else {
				fmt.Fprintf(wr, "%v\n", p.Get(f.PayloadIndex))
			}
		}
		return nil
	})
}

func (ds *dataSource) Fields() []*api.Field {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	res := make([]*api.Field, 0, len(ds.fields))
	for _, f := range ds.fields {
		res = append(res, (*api.Field)(f))
	}
	return res
}

func (ds *dataSource) Accessors(rootOnly bool) []FieldAccessor {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	res := make([]FieldAccessor, 0, len(ds.fields))
	for _, f := range ds.fields {
		if rootOnly && FieldFlagHasParent.In(f.Flags) {
			continue
		}
		res = append(res, &fieldAccessor{
			ds: ds,
			f:  f,
		})
	}
	return res
}

func (ds *dataSource) IsRequested() bool {
	ds.lock.RLock()
	defer ds.lock.RUnlock()
	return ds.requested
}

func (ds *dataSource) AddAnnotation(key, value string) {
	ds.lock.Lock()
	defer ds.lock.Unlock()
	ds.annotations[key] = value
}

func (ds *dataSource) AddTag(tag string) {
	ds.lock.Lock()
	defer ds.lock.Unlock()
	ds.tags = append(ds.tags, tag)
}

func (ds *dataSource) Annotations() map[string]string {
	ds.lock.RLock()
	defer ds.lock.RUnlock()
	return maps.Clone(ds.annotations)
}

func (ds *dataSource) Tags() []string {
	ds.lock.RLock()
	defer ds.lock.RUnlock()
	return slices.Clone(ds.tags)
}
