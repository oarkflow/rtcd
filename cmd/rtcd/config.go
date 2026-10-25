package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oarkflow/bcl"
)

// loadConfig reads rtcd.bcl. A secret comes from the environment with
// env.required("NAME") (the service will not start without it) or env("NAME",
// "default"), so it never has to be written in the file:
//
//	listen "127.0.0.1:8480"
//
//	database { driver "sqlite"  dsn "file:.data/rtcd.db?_pragma=busy_timeout(5000)" }
//	audit    { dsn "file:.data/audit.db"  file ".data/audit.jsonl" }
//
//	key "my-backend" { key env.required("RTCD_API_KEY")  tenant "acme" }
//	token_secret env.required("RTCD_TOKEN_SECRET")
//
//	allowed_origins ["https://app.example.com"]
//	limits { ops_per_second 200  max_connections 20000 }
//
// A setting the service does not know is an error, not a silent default.
func loadConfig(path string) (fileConfig, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return fileConfig{}, err
	}
	return parseConfig(src, filepath.Dir(path))
}

func parseConfig(src []byte, baseDir string) (fileConfig, error) {
	var fc fileConfig
	n, err := bcl.CompileBytes(src, &bcl.Options{AllowEnv: true, BaseDir: baseDir})
	if err != nil {
		return fc, fmt.Errorf("config: %w", err)
	}
	settings := map[string]any{}
	for k, v := range n.Body {
		settings[k] = v
	}
	if _, bare := settings["key"]; bare {
		return fc, fmt.Errorf("config: a key block needs a name: key \"my-backend\" { … }")
	}
	// key "name" { key … tenant … } blocks are the service keys. A block with no
	// name (audit { … }, limits { … }) is a group of settings; BCL gives some
	// words, audit among them, a meaning of their own, so those arrive as blocks.
	for _, b := range n.Blocks {
		typ, _ := b["type"].(string)
		id, _ := b["id"].(string)
		body, _ := b["body"].(map[string]any)
		if typ != "key" {
			if id != "" {
				return fc, fmt.Errorf("config: unknown block %q (expected key \"name\" { … })", typ)
			}
			if _, dup := settings[typ]; dup {
				return fc, fmt.Errorf("config: %q is set twice", typ)
			}
			settings[typ] = body
			continue
		}
		if id == "" {
			return fc, fmt.Errorf("config: a key block needs a name: key \"my-backend\" { … }")
		}
		fc.Keys = append(fc.Keys, configKey{Name: id})
		raw, err := json.Marshal(body)
		if err != nil {
			return fc, err
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&fc.Keys[len(fc.Keys)-1]); err != nil {
			return fc, fmt.Errorf("config: key %q: %w", id, err)
		}
		fc.Keys[len(fc.Keys)-1].Name = id
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return fc, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() // a misspelt setting is an error
	if err := dec.Decode(&fc); err != nil {
		return fc, fmt.Errorf("config: %s", strings.TrimPrefix(err.Error(), "json: "))
	}
	return fc, nil
}
