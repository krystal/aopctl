package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/invopop/jsonschema"
	sjsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

var updateSchema = flag.Bool("update", false, "write the config file's JSON schema to "+schemaPath)

const (
	schemaPath = "../schemas/config.schema.json"
	// schemaID is where each release publishes the schema.
	schemaID = "https://github.com/krystal/aopctl/releases/latest/download/config.schema.json"
)

// configSchema generates the config file's JSON schema from fileConfig.
// Everything is inline, without $defs, so editors on older drafts read it
// the same way.
func configSchema() *jsonschema.Schema {
	r := &jsonschema.Reflector{
		FieldNameTag:               "yaml",
		RequiredFromJSONSchemaTags: true,
		ExpandedStruct:             true,
		DoNotReference:             true,
	}
	s := r.Reflect(&fileConfig{})
	s.ID = schemaID
	profiles, _ := s.Properties.Get("profiles")
	profiles.PropertyNames = &jsonschema.Schema{Pattern: profileNamePattern.String()}
	return s
}

func TestConfigSchema(t *testing.T) {
	got, err := json.MarshalIndent(configSchema(), "", "  ")
	require.NoError(t, err, "marshal schema")
	got = append(got, '\n')
	if *updateSchema {
		require.NoError(t, os.WriteFile(schemaPath, got, 0o644), "write schema") //nolint:gosec // a public file
		return
	}
	want, err := os.ReadFile(schemaPath)
	require.NoError(t, err, "read schema")
	assert.Equal(t, string(want), string(got), "schemas/config.schema.json is out of date: run mise run generate:schema")
}

// readmeConfig returns the example config file in README.md.
func readmeConfig(t *testing.T) string {
	t.Helper()
	readme, err := os.ReadFile("../README.md")
	require.NoError(t, err, "read README.md")
	// Git checks README.md out with CRLF line endings on Windows.
	text := strings.ReplaceAll(string(readme), "\r\n", "\n")
	_, example, ok := strings.Cut(text, "```yaml\n# ~/.config/aopctl/config.yaml\n")
	require.True(t, ok, "no example config file in README.md")
	example, _, ok = strings.Cut(example, "```")
	require.True(t, ok, "unterminated example config file in README.md")
	return example
}

// compileSchema compiles the committed schema.
func compileSchema(t *testing.T) *sjsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(schemaPath)
	require.NoError(t, err, "read schema")
	doc, err := sjsonschema.UnmarshalJSON(bytes.NewReader(data))
	require.NoError(t, err, "parse schema")
	c := sjsonschema.NewCompiler()
	require.NoError(t, c.AddResource(schemaID, doc), "add schema")
	s, err := c.Compile(schemaID)
	require.NoError(t, err, "compile schema")
	return s
}

// validateYAML validates a YAML document against s as an editor does:
// with YAML's own types, and not at all when the document is empty.
func validateYAML(t *testing.T, s *sjsonschema.Schema, content string) error {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(content), &node), "parse YAML")
	if node.Kind == 0 {
		return nil
	}
	var v any
	require.NoError(t, node.Decode(&v), "decode YAML")
	data, err := json.Marshal(v)
	require.NoError(t, err, "YAML as JSON")
	doc, err := sjsonschema.UnmarshalJSON(bytes.NewReader(data))
	require.NoError(t, err, "parse JSON")
	return s.Validate(doc)
}

func TestConfigSchemaValidation(t *testing.T) {
	schema := compileSchema(t)
	tests := []struct {
		name    string
		content string
		// decodes and validates are whether aopctl and the schema accept
		// the file. They differ only where the schema is deliberately
		// stricter, to flag values that aopctl reads as unset or as text.
		decodes   bool
		validates bool
	}{
		{name: "README example", content: readmeConfig(t), decodes: true, validates: true},
		{name: "empty file", content: "", decodes: true, validates: true},
		{name: "unknown top-level key", content: "ca_certs: x\n"},
		{name: "unknown profile key", content: "profiles:\n  prod:\n    hostname: [a.example.com]\n"},
		{name: "invalid profile name", content: "profiles:\n  'a b': {}\n"},
		{name: "hostnames as a scalar", content: "hostnames: a.example.com\n"},
		{name: "null hostnames", content: "hostnames:\n", decodes: true},
		{name: "empty profile", content: "profiles:\n  prod:\n", decodes: true},
		{name: "number as a string", content: "ca_key: 123\n", decodes: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := configApp(t, nil, "--config", writeConfig(t, tt.content)).readConfigFile()
			assert.Equal(t, tt.decodes, err == nil, "decodes; error: %v", err)
			err = validateYAML(t, schema, tt.content)
			assert.Equal(t, tt.validates, err == nil, "validates; error: %v", err)
		})
	}
}
