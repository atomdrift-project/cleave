package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"
)

//go:embed bad_prompt.tmpl
var badPromptTemplate string

//go:embed good_prompt.tmpl
var goodPromptTemplate string

//go:embed tools.tmpl
var toolsTemplate string

var (
	badTmpl   *template.Template
	goodTmpl  *template.Template
	toolsTmpl *template.Template
)

func loadPromptTemplate(_ string) error {
	var err error

	toolsTmpl, err = template.New("tools").Parse(toolsTemplate)
	if err != nil {
		return fmt.Errorf("parse tools template: %w", err)
	}

	badTmpl, err = template.New("bad").Parse(badPromptTemplate)
	if err != nil {
		return fmt.Errorf("parse bad prompt template: %w", err)
	}

	goodTmpl, err = template.New("good").Parse(goodPromptTemplate)
	if err != nil {
		return fmt.Errorf("parse good prompt template: %w", err)
	}

	return nil
}

// buildPrompt constructs the full prompt by combining the mode-specific template with shared tools.
func buildPrompt(data *promptData) string {
	var main bytes.Buffer
	var tools bytes.Buffer

	if data.IsBad {
		_ = badTmpl.Execute(&main, data) //nolint:errcheck // template execution errors are non-critical for prompts
	} else {
		_ = goodTmpl.Execute(&main, data) //nolint:errcheck // template execution errors are non-critical for prompts
	}

	_ = toolsTmpl.Execute(&tools, data) //nolint:errcheck // template execution errors are non-critical for prompts

	return main.String() + "\n" + tools.String()
}
