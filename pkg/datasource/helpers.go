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

func (ds *dataSource) SetVisibleFields(fields []string) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	// Use default if fields is nil
	if fields == nil {
		return
	}
	allRelative := false
	showFields := make(map[string]struct{})
	hideFields := make(map[string]struct{})

	for _, f := range fields {
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case '+':
			showFields[f[1:]] = struct{}{}
		case '-':
			hideFields[f[1:]] = struct{}{}
		default:
			showFields[f] = struct{}{}
			allRelative = false
		}
	}

	for _, f := range ds.fields {
		if _, ok := showFields[f.Name]; ok {
			FieldFlagHidden.RemoveFrom(&f.Flags)
			continue
		}
		if !allRelative {
			FieldFlagHidden.AddTo(&f.Flags)
			continue
		}
		if _, ok := hideFields[f.Name]; ok {
			FieldFlagHidden.AddTo(&f.Flags)
			continue
		}
	}
}
