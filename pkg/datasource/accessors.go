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
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

// FieldAccessor grants access to the underlying buffer of a field
type FieldAccessor interface {
	Name() string

	// Size returns the expected size of the underlying field or zero, if the field has a dynamic size
	Size() uint32

	// Get returns the underlying memory of the field
	Get(Payload) []byte

	// Set sets value as the new reference for the field; if the FieldAccessor is used for the member of a
	// statically sized payload (for example a member of an eBPF struct), value will be copied to the existing
	// memory instead.
	Set(Payload, []byte) error

	// IsRequested returns whether the consumer is interested in this field; if not, operators are not required
	// to fill them out
	IsRequested() bool

	// AddSubField adds a new field as member of the current field; be careful when doing this on an existing
	// non-empty field, as that might be dropped on serialization // TODO
	AddSubField(name string, opts ...FieldOption) (FieldAccessor, error)

	// GetSubFieldsWithTag returns all SubFields matching any given tag
	GetSubFieldsWithTag(tag ...string) []FieldAccessor

	// Parent returns the parent of this field, if this field is a SubField
	Parent() FieldAccessor

	// SubFields returns all existing SubFields of the current field
	SubFields() []FieldAccessor

	// SetHidden marks a field as hidden (by default) - it can still be requested
	SetHidden(bool)

	// Type returns the underlying type of the field
	Type() api.Kind

	// Flags returns the flags of the field
	Flags() uint32

	// Annotations returns stored annotations of the field
	Annotations() map[string]string

	Uint8(Payload) uint8
	Uint16(Payload) uint16
	Uint32(Payload) uint32
	Uint64(Payload) uint64
	Int8(Payload) int8
	Int16(Payload) int16
	Int32(Payload) int32
	Int64(Payload) int64

	PutUint8(Payload, uint8)
	PutUint16(Payload, uint16)
	PutUint32(Payload, uint32)
	PutUint64(Payload, uint64)
	PutInt8(Payload, int8)
	PutInt16(Payload, int16)
	PutInt32(Payload, int32)
	PutInt64(Payload, int64)

	String(Payload) string
	CString(Payload) string
}

type fieldAccessor struct {
	ds *dataSource
	f  *field
}

func (a *fieldAccessor) Name() string {
	return a.f.Name
}

func (a *fieldAccessor) Size() uint32 {
	return a.f.Size
}

func (a *fieldAccessor) Type() api.Kind {
	return a.f.Kind
}

func (a *fieldAccessor) Get(p Payload) []byte {
	if FieldFlagEmpty.In(a.f.Flags) {
		return nil
	}
	if a.f.Size > 0 {
		// size and offset must be valid here; checks take place on initialization
		return p.GetChunk(a.f.PayloadIndex, a.f.Offs, a.f.Size)
	}
	return p.Get(a.f.PayloadIndex)
}

func (a *fieldAccessor) SetHidden(val bool) {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()
	if !val {
		FieldFlagHidden.RemoveFrom(&a.f.Flags)
	} else {
		FieldFlagHidden.AddTo(&a.f.Flags)
	}
}

func (a *fieldAccessor) Set(p Payload, b []byte) error {
	if FieldFlagEmpty.In(a.f.Flags) {
		return errors.New("field cannot contain a value")
	}
	if FieldFlagStaticMember.In(a.f.Flags) {
		if uint32(len(b)) != a.f.Size {
			return fmt.Errorf("invalid size, expected %d, got %d", a.f.Size, len(b))
		}
		p.SetChunk(a.f.PayloadIndex, a.f.Offs, a.f.Size, b)
		return nil
	}
	p.Set(a.f.PayloadIndex, b)
	return nil
}

func (a *fieldAccessor) AddSubField(name string, opts ...FieldOption) (FieldAccessor, error) {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()

	parentFullName, err := resolveNames(a.f.Index, a.ds.fields, 0)
	if err != nil {
		return nil, fmt.Errorf("resolving parent field name: %w", err)
	}

	nf := &field{
		Name:     name,
		FullName: parentFullName + "." + name,
		Kind:     api.Kind_Invalid,
		Parent:   a.f.Index,
		Index:    uint32(len(a.ds.fields)),
	}
	for _, opt := range opts {
		opt(nf)
	}

	if _, ok := a.ds.fieldMap[nf.FullName]; ok {
		return nil, fmt.Errorf("field with name %q already exists", nf.FullName)
	}

	FieldFlagHasParent.AddTo(&nf.Flags)

	if !FieldFlagEmpty.In(nf.Flags) {
		nf.PayloadIndex = a.ds.payloadCount
		a.ds.payloadCount++
	}

	a.ds.fields = append(a.ds.fields, nf)
	a.ds.fieldMap[nf.FullName] = nf

	a.ds.logger.Debugf("new dynamic sub-field: name %s (parent %s) PayloadIndex %d size %d\n",
		name, a.ds.fields[nf.Parent].Name, nf.PayloadIndex, nf.Size)

	return &fieldAccessor{ds: a.ds, f: nf}, nil
}

func (a *fieldAccessor) SubFields() []FieldAccessor {
	var res []FieldAccessor
	for _, f := range a.ds.fields {
		if !FieldFlagHasParent.In(f.Flags) {
			continue
		}
		if f.Parent != a.f.Index {
			continue
		}
		res = append(res, &fieldAccessor{
			ds: a.ds,
			f:  f,
		})
	}
	return res
}

func (a *fieldAccessor) Parent() FieldAccessor {
	if !FieldFlagHasParent.In(a.f.Flags) {
		return nil
	}
	if a.f.Parent >= uint32(len(a.ds.fields)) {
		return nil
	}
	return &fieldAccessor{ds: a.ds, f: a.ds.fields[a.f.Parent]}
}

func (a *fieldAccessor) GetSubFieldsWithTag(tag ...string) []FieldAccessor {
	res := make([]FieldAccessor, 0)
	for _, f := range a.ds.fields {
		if !FieldFlagHasParent.In(f.Flags) {
			continue
		}
		if f.Parent != a.f.Index {
			continue
		}
		for _, t := range tag {
			if slices.Contains(f.Tags, t) {
				res = append(res, &fieldAccessor{ds: a.ds, f: f})
				break
			}
		}
	}
	return res
}

func (a *fieldAccessor) IsRequested() bool {
	return a.ds.IsRequestedField(a.f.Name)
}

func (a *fieldAccessor) Flags() uint32 {
	return a.f.Flags
}

func (a *fieldAccessor) Annotations() map[string]string {
	if a.f.Annotations == nil {
		// Return an empty map to allow access without prior checks
		return map[string]string{}
	}
	// return a clone to avoid write access
	return maps.Clone(a.f.Annotations)
}

func (a *fieldAccessor) Uint8(p Payload) uint8 {
	return a.Get(p)[0]
}

func (a *fieldAccessor) Uint16(p Payload) uint16 {
	return a.ds.byteOrder.Uint16(a.Get(p))
}

func (a *fieldAccessor) Uint32(p Payload) uint32 {
	return a.ds.byteOrder.Uint32(a.Get(p))
}

func (a *fieldAccessor) Uint64(p Payload) uint64 {
	return a.ds.byteOrder.Uint64(a.Get(p))
}

func (a *fieldAccessor) Int8(p Payload) int8 {
	return int8(a.Get(p)[0])
}

func (a *fieldAccessor) Int16(p Payload) int16 {
	return int16(a.ds.byteOrder.Uint16(a.Get(p)))
}

func (a *fieldAccessor) Int32(p Payload) int32 {
	return int32(a.ds.byteOrder.Uint32(a.Get(p)))
}

func (a *fieldAccessor) Int64(p Payload) int64 {
	return int64(a.ds.byteOrder.Uint64(a.Get(p)))
}

func (a *fieldAccessor) String(p Payload) string {
	return string(a.Get(p))
}

func (a *fieldAccessor) CString(p Payload) string {
	return gadgets.FromCString(a.Get(p))
}

func (a *fieldAccessor) PutUint8(p Payload, val uint8) {
	a.Get(p)[0] = val
}

func (a *fieldAccessor) PutUint16(p Payload, val uint16) {
	a.ds.byteOrder.PutUint16(a.Get(p), val)
}

func (a *fieldAccessor) PutUint32(p Payload, val uint32) {
	a.ds.byteOrder.PutUint32(a.Get(p), val)
}

func (a *fieldAccessor) PutUint64(p Payload, val uint64) {
	a.ds.byteOrder.PutUint64(a.Get(p), val)
}

func (a *fieldAccessor) PutInt8(p Payload, val int8) {
	a.Get(p)[0] = uint8(val)
}

func (a *fieldAccessor) PutInt16(p Payload, val int16) {
	a.ds.byteOrder.PutUint16(a.Get(p), uint16(val))
}

func (a *fieldAccessor) PutInt32(p Payload, val int32) {
	a.ds.byteOrder.PutUint32(a.Get(p), uint32(val))
}

func (a *fieldAccessor) PutInt64(p Payload, val int64) {
	a.ds.byteOrder.PutUint64(a.Get(p), uint64(val))
}
