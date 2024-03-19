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
	"net"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	kprobePrefix    = "kprobe/"
	kretprobePrefix = "kretprobe/"
	iterPrefix      = "iter/"
	fentryPrefix    = "fentry/"
	fexitPrefix     = "fexit/"
)

func (i *ebpfInstance) attachProgram(gadgetCtx operators.GadgetContext, p *ebpf.ProgramSpec, prog *ebpf.Program) (link.Link, error) {
	switch p.Type {
	case ebpf.Kprobe:
		switch {
		case strings.HasPrefix(p.SectionName, kprobePrefix):
			i.logger.Debugf("Attaching kprobe %q to %q", p.Name, p.AttachTo)
			return link.Kprobe(p.AttachTo, prog, nil)
		case strings.HasPrefix(p.SectionName, kretprobePrefix):
			i.logger.Debugf("Attaching kretprobe %q to %q", p.Name, p.AttachTo)
			return link.Kretprobe(p.AttachTo, prog, nil)

		case strings.HasPrefix(p.SectionName, "uprobe/") || strings.HasPrefix(p.SectionName, "uretprobe/"):
			captureHost := false
			for _, container := range i.containers {
				if container.Pid == 1 {
					captureHost = true
				}
			}
			if !captureHost {
				return nil, fmt.Errorf("uprobe can only be used with --host at this moment")
			}

			parts := strings.Split(p.AttachTo, ":")
			if len(parts) < 2 {
				return nil, fmt.Errorf("invalid section name %q", p.AttachTo)
			}
			if !filepath.IsAbs(parts[0]) {
				return nil, fmt.Errorf("section name is not an absolute path: %q", parts[0])
			}
			executablePath := filepath.Join(host.HostProcFs, "1/root", parts[0])
			ex, err := link.OpenExecutable(executablePath)
			if err != nil {
				return nil, fmt.Errorf("opening executable: %q", executablePath)
			}

			i.logger.Debugf("Attaching uprobe %q to %q", p.Name, p.AttachTo)
			switch strings.Split(p.SectionName, "/")[0] {
			case "uprobe":
				return ex.Uprobe(parts[1], prog, nil)
			case "uretprobe":
				return ex.Uretprobe(parts[1], prog, nil)
			}
		}
		return nil, fmt.Errorf("unsupported section name %q for program %q", p.SectionName, p.Name)
	case ebpf.TracePoint:
		i.logger.Debugf("Attaching tracepoint %q to %q", p.Name, p.AttachTo)
		parts := strings.Split(p.AttachTo, "/")
		return link.Tracepoint(parts[0], parts[1], prog, nil)
	case ebpf.SocketFilter:
		i.logger.Debugf("Attaching socket filter %q to %q", p.Name, p.AttachTo)
		networkTracer := i.networkTracers[p.Name]
		return nil, networkTracer.AttachProg(prog)
	case ebpf.Tracing:
		switch {
		case strings.HasPrefix(p.SectionName, iterPrefix):
			i.logger.Debugf("Attaching iter %q to %q", p.Name, p.AttachTo)
			switch p.AttachTo {
			case "task", "tcp", "udp":
				return link.AttachIter(link.IterOptions{
					Program: prog,
				})
			}
			return nil, fmt.Errorf("unsupported iter type %q", p.AttachTo)
		case strings.HasPrefix(p.SectionName, fentryPrefix):
			i.logger.Debugf("Attaching fentry %q to %q", p.Name, p.AttachTo)
			return link.AttachTracing(link.TracingOptions{
				Program:    prog,
				AttachType: ebpf.AttachTraceFEntry,
			})
		case strings.HasPrefix(p.SectionName, fexitPrefix):
			i.logger.Debugf("Attaching fexit %q to %q", p.Name, p.AttachTo)
			return link.AttachTracing(link.TracingOptions{
				Program:    prog,
				AttachType: ebpf.AttachTraceFExit,
			})
		}
		return nil, fmt.Errorf("unsupported section name %q for program %q as type ebpf.Tracing", p.SectionName, p.Name)
	case ebpf.RawTracepoint:
		i.logger.Debugf("Attaching raw tracepoint %q to %q", p.Name, p.AttachTo)
		return link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    p.AttachTo,
			Program: prog,
		})
	case ebpf.SchedCLS:
		handler := i.tcHandlers[p.Name]

		if i.ifaceName != "" {
			iface, err := net.InterfaceByName(i.ifaceName)
			if err != nil {
				return nil, fmt.Errorf("getting interface %q: %w", i.ifaceName, err)
			}

			if err := handler.AttachIface(iface); err != nil {
				return nil, fmt.Errorf("attaching iface %q: %w", i.ifaceName, err)
			}
		}

		i.logger.Debugf("Attaching sched_cls %q", p.Name)
		return nil, handler.AttachProg(prog)
	default:
		return nil, fmt.Errorf("unsupported program %q of type %q", p.Name, p.Type)
	}
}