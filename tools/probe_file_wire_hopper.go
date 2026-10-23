// Run from ../hopper: go run ../cleave/tools/probe_file_wire_hopper.go CASE_DIRECTORY
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	hopper "github.com/atomdrift-project/hopper"
	"os"
	"path/filepath"
	"reflect"
)

func parsed(b []byte) any {
	var v any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := d.Decode(&v); e != nil {
		panic(e)
	}
	return v
}
func main() {
	root := os.Args[1]
	entries, err := os.ReadDir(root)
	if err != nil {
		panic(err)
	}
	var results []map[string]any
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		folder := filepath.Join(root, entry.Name())
		for _, variant := range []string{"v8", "trimmed"} {
			data, e := os.ReadFile(filepath.Join(folder, variant+".json"))
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				panic(e)
			}
			env, _ := json.Marshal(map[string]json.RawMessage{"raw": data})
			parent, leaves, e := hopper.Split(env)
			if e != nil {
				panic(e)
			}
			bySHA := map[string][]byte{}
			for _, leaf := range leaves {
				bySHA[leaf.SHA256] = leaf.Envelope
			}
			joined, e := hopper.Join(parent, func(sha string) ([]byte, bool) { v, ok := bySHA[sha]; return v, ok })
			if e != nil {
				panic(e)
			}
			equal := reflect.DeepEqual(parsed(env), parsed(joined))
			size := len(parent)
			for _, v := range bySHA {
				size += len(v)
			}
			results = append(results, map[string]any{"sample": entry.Name(), "variant": variant, "equal": equal, "leaves": len(leaves), "unique_leaves": len(bySHA), "joined_bytes": len(env), "split_bytes": size})
			if variant == "trimmed" {
				if e = os.WriteFile(filepath.Join(folder, "hopper.joined.json"), joined, 0600); e != nil {
					panic(e)
				}
			}
			fmt.Fprintf(os.Stderr, "%s %s: equal=%t, leaves=%d\n", entry.Name(), variant, equal, len(leaves))
		}
	}
	out, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(filepath.Join(root, "hopper-measurements.json"), out, 0600); err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
