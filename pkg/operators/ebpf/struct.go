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
	"fmt"
	"reflect"

	"github.com/cilium/ebpf/btf"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfhelpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
)

type Field struct {
	metadatav1.Field
	Tags   []string
	Type   reflect.Type
	Offset uint32
	parent int
	name   string
}

type Struct struct {
	Fields []*Field `yaml:"fields"`
	Size   uint32
}

func (f *Field) FieldName() string {
	return f.name
}

func (f *Field) FieldSize() uint32 {
	return f.Size
}

func (f *Field) FieldOffset() uint32 {
	return f.Offset
}

func (f *Field) FieldTags() []string {
	return f.Tags
}

func (f *Field) FieldType() api.Kind {
	if f.Type == nil {
		return api.Kind_Invalid
	}
	switch f.Type.Kind() {
	case reflect.Bool:
		return api.Kind_Bool
	case reflect.Int8:
		return api.Kind_Int8
	case reflect.Int16:
		return api.Kind_Int16
	case reflect.Int32:
		return api.Kind_Int32
	case reflect.Int64:
		return api.Kind_Int64
	case reflect.Uint8:
		return api.Kind_Uint8
	case reflect.Uint16:
		return api.Kind_Uint16
	case reflect.Uint32:
		return api.Kind_Uint32
	case reflect.Uint64:
		return api.Kind_Uint64
	case reflect.Float32:
		return api.Kind_Float32
	case reflect.Float64:
		return api.Kind_Float64
	}
	return api.Kind_Invalid
}

func (f *Field) FieldDescription() string { return f.Description }

func (f *Field) FieldAnnotations() map[string]any { return f.Annotations }

func (f *Field) FieldParent() int {
	return f.parent
}

func (i *ebpfInstance) populateStructDirect(btfStruct *btf.Struct) error {
	gadgetStruct := i.structs[btfStruct.Name]
	existingFields := make(map[string]*Field)

	if gadgetStruct == nil {
		gadgetStruct = &Struct{}
		i.logger.Debugf("adding struct %q", btfStruct.Name)
	}

	// TODO: make this validate the struct
	for _, field := range gadgetStruct.Fields {
		existingFields[field.Name] = field
	}

	i.getFieldsFromStruct(btfStruct, &gadgetStruct.Fields, "", 0, -1)

	var configStruct *metadatav1.Struct
	fields := i.config.Sub("structs." + btfStruct.Name)
	if fields != nil {
		// This feels ugly, maybe optimize
		d, _ := yaml.Marshal(fields.AllSettings())
		err := yaml.Unmarshal(d, &configStruct)
		if err != nil {
			return fmt.Errorf("invalid metadata for struct %q", btfStruct.Name)
		}

		// Build lookup
		lookup := make(map[string]metadatav1.Field)
		for _, field := range configStruct.Fields {
			lookup[field.Name] = field
		}

		// Only handling topmost layer for now // TODO
		for _, field := range gadgetStruct.Fields {
			cfgField, ok := lookup[field.Name]
			if !ok {
				continue
			}
			i.logger.Debugf(" found field config for %q", field.Name)
			if cfgField.Size > 0 && cfgField.Size != field.Size {
				return fmt.Errorf("field size mismatch for field %q", field.Name)
			}

			// Fill in blanks from metadata
			field.Description = cfgField.Description
			field.Attributes = cfgField.Attributes
			field.Annotations = cfgField.Annotations
		}
	}

	gadgetStruct.Size = btfStruct.Size

	i.structs[btfStruct.Name] = gadgetStruct
	return nil
}

func (i *ebpfInstance) getFieldsFromMember(member btf.Member, fields *[]*Field, prefix string, offset uint32, parent int) {
	refType, tags := btfhelpers.GetType(member.Type)
	for i := range tags {
		tags[i] = "type:" + tags[i]
	}

	tags = append(tags, "name:"+member.Name, "src:ebpf")

	// Flatten embedded structs
	if t, ok := member.Type.(*btf.Struct); ok {
		// Add outer struct as well
		field := &Field{
			Field: metadatav1.Field{
				Name:        prefix + member.Name,
				Size:        t.Size,
				Description: "",
				Attributes: metadatav1.FieldAttributes{
					// Width:     getColumnSize(member.Type), // TODO: get using columns pkg with help of refType
					Alignment: metadatav1.AlignmentLeft,
					Ellipsis:  metadatav1.EllipsisEnd,
				},
			},
			Tags:   tags,
			Type:   reflect.ArrayOf(int(t.Size), reflect.TypeOf(uint8(0))),
			Offset: offset + member.Offset.Bytes(), // TODO: do we need bits?!
			parent: parent,
			name:   member.Name,
		}
		newParent := len(*fields)
		*fields = append(*fields, field)

		i.logger.Debugf(" adding field %q (%s) at %d (%v)", field.Name, "struct", field.Offset, tags)
		i.getFieldsFromStruct(t, fields, prefix+member.Name+".", offset+member.Offset.Bytes(), newParent)
		return
	}

	if t, ok := member.Type.(*btf.Union); ok {
		// Add outer struct as well
		field := &Field{
			Field: metadatav1.Field{
				Name:        prefix + member.Name,
				Size:        t.Size,
				Description: "",
				Attributes: metadatav1.FieldAttributes{
					// Width:     getColumnSize(member.Type), // TODO: get using columns pkg with help of refType
					Alignment: metadatav1.AlignmentLeft,
					Ellipsis:  metadatav1.EllipsisEnd,
				},
			},
			Tags:   tags,
			Type:   reflect.ArrayOf(int(t.Size), reflect.TypeOf(uint8(0))),
			Offset: offset + member.Offset.Bytes(), // TODO: do we need bits?!
			parent: parent,
			name:   member.Name,
		}
		newParent := len(*fields)
		*fields = append(*fields, field)

		i.logger.Debugf(" adding field %q (%s) at %d", field.Name, "union", field.Offset)
		i.getFieldsFromUnion(t, fields, prefix+member.Name+".", offset+member.Offset.Bytes(), newParent)
		return
	}

	fsize := uint32(0)
	fieldType := "raw bytes"
	if refType != nil {
		fsize = uint32(refType.Size())
		fieldType = refType.String()
	}

	// handling arrays as raw data
	if arr, ok := member.Type.(*btf.Array); ok {
		// make sure type
		arrType := arr.Type

		// Resolve
		if typedef, ok := arrType.(*btf.Typedef); ok {
			arrType = btfhelpers.GetUnderlyingType(typedef)
		}

		intType, ok := arrType.(*btf.Int)
		if !ok {
			i.logger.Debugf(" skipping field %q (%T) (array of non-int %T)", prefix+member.Name, member.Type, arr.Type)
			return
		}
		if intType.Size != 1 {
			i.logger.Debugf(" skipping field %q (%T) (array of elements with size != 1)", prefix+member.Name, member.Type)
			return
		}
		fsize = intType.Size * arr.Nelems
	}

	if fsize == 0 {
		i.logger.Debugf(" skipping field %q (%T)", prefix+member.Name, member.Type)
		return
	}

	// Keep enums to convert them to strings
	if enum, ok := member.Type.(*btf.Enum); ok {
		i.enums[member.Name] = enum
	}

	// TODO: iterate through typedefs and add them as tags
	field := &Field{
		Field: metadatav1.Field{
			Name:        prefix + member.Name,
			Size:        fsize,
			Description: "",
			Attributes: metadatav1.FieldAttributes{
				// Width:     getColumnSize(member.Type), // TODO: get using columns pkg with help of refType
				Alignment: metadatav1.AlignmentLeft,
				Ellipsis:  metadatav1.EllipsisEnd,
			},
		},
		Tags:   tags,
		Type:   refType,
		Offset: offset + member.Offset.Bytes(), // TODO: do we need bits?!
		parent: parent,
		name:   member.Name,
	}
	i.logger.Debugf(" adding field %q (%s) at %d (parent %d) (%v)", field.Name, fieldType, field.Offset, parent, tags)
	*fields = append(*fields, field)
}

func (i *ebpfInstance) getFieldsFromStruct(btfStruct *btf.Struct, fields *[]*Field, prefix string, offset uint32, parent int) {
	for _, member := range btfStruct.Members {
		i.getFieldsFromMember(member, fields, prefix, offset, parent)
	}
}

func (i *ebpfInstance) getFieldsFromUnion(btfStruct *btf.Union, fields *[]*Field, prefix string, offset uint32, parent int) {
	for _, member := range btfStruct.Members {
		i.getFieldsFromMember(member, fields, prefix, offset, parent)
	}
}
