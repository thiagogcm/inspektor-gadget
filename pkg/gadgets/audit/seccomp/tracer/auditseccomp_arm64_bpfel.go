// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type auditseccompEvent struct {
	Pid       uint64
	MntnsId   uint64
	Timestamp uint64
	Syscall   uint64
	Code      uint64
	Comm      [16]uint8
}

// loadAuditseccomp returns the embedded CollectionSpec for auditseccomp.
func loadAuditseccomp() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_AuditseccompBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load auditseccomp: %w", err)
	}

	return spec, err
}

// loadAuditseccompObjects loads auditseccomp and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*auditseccompObjects
//	*auditseccompPrograms
//	*auditseccompMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadAuditseccompObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadAuditseccomp()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// auditseccompSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type auditseccompSpecs struct {
	auditseccompProgramSpecs
	auditseccompMapSpecs
}

// auditseccompSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type auditseccompProgramSpecs struct {
	IgAuditSecc *ebpf.ProgramSpec `ebpf:"ig_audit_secc"`
}

// auditseccompMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type auditseccompMapSpecs struct {
	Events               *ebpf.MapSpec `ebpf:"events"`
	GadgetMntnsFilterMap *ebpf.MapSpec `ebpf:"gadget_mntns_filter_map"`
	TmpEvent             *ebpf.MapSpec `ebpf:"tmp_event"`
}

// auditseccompObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadAuditseccompObjects or ebpf.CollectionSpec.LoadAndAssign.
type auditseccompObjects struct {
	auditseccompPrograms
	auditseccompMaps
}

func (o *auditseccompObjects) Close() error {
	return _AuditseccompClose(
		&o.auditseccompPrograms,
		&o.auditseccompMaps,
	)
}

// auditseccompMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadAuditseccompObjects or ebpf.CollectionSpec.LoadAndAssign.
type auditseccompMaps struct {
	Events               *ebpf.Map `ebpf:"events"`
	GadgetMntnsFilterMap *ebpf.Map `ebpf:"gadget_mntns_filter_map"`
	TmpEvent             *ebpf.Map `ebpf:"tmp_event"`
}

func (m *auditseccompMaps) Close() error {
	return _AuditseccompClose(
		m.Events,
		m.GadgetMntnsFilterMap,
		m.TmpEvent,
	)
}

// auditseccompPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadAuditseccompObjects or ebpf.CollectionSpec.LoadAndAssign.
type auditseccompPrograms struct {
	IgAuditSecc *ebpf.Program `ebpf:"ig_audit_secc"`
}

func (p *auditseccompPrograms) Close() error {
	return _AuditseccompClose(
		p.IgAuditSecc,
	)
}

func _AuditseccompClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed auditseccomp_arm64_bpfel.o
var _AuditseccompBytes []byte