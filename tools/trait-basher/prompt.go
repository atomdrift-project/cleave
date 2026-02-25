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

//go:embed repair_prompt.tmpl
var repairPromptTemplate string

//go:embed tools.tmpl
var toolsTemplate string

var (
	badTmpl    *template.Template
	goodTmpl   *template.Template
	repairTmpl *template.Template
	toolsTmpl  *template.Template
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

	repairTmpl, err = template.New("repair").Parse(repairPromptTemplate)
	if err != nil {
		return fmt.Errorf("parse repair prompt template: %w", err)
	}

	return nil
}

// buildPrompt constructs the full prompt by combining the mode-specific template with shared tools.
func buildPrompt(data *promptData) (string, error) {
	var main bytes.Buffer
	var tools bytes.Buffer

	if data.IsBad {
		if err := badTmpl.Execute(&main, data); err != nil {
			return "", fmt.Errorf("execute bad prompt template: %w", err)
		}
	} else {
		if err := goodTmpl.Execute(&main, data); err != nil {
			return "", fmt.Errorf("execute good prompt template: %w", err)
		}
	}

	if err := toolsTmpl.Execute(&tools, data); err != nil {
		return "", fmt.Errorf("execute tools template: %w", err)
	}

	return main.String() + "\n" + tools.String(), nil
}

// repairPromptData holds values for the repair prompt template.
type repairPromptData struct {
	Phase         string
	FailureOutput string
	CleaveBin     string
	TraitsDir     string
	Path          string // For tools.tmpl compatibility
}

// buildRepairPrompt constructs the repair prompt with tools reference.
func buildRepairPrompt(data *repairPromptData) (string, error) {
	var main bytes.Buffer
	var tools bytes.Buffer

	if err := repairTmpl.Execute(&main, data); err != nil {
		return "", fmt.Errorf("execute repair prompt template: %w", err)
	}

	if err := toolsTmpl.Execute(&tools, data); err != nil {
		return "", fmt.Errorf("execute tools template: %w", err)
	}

	return main.String() + "\n" + tools.String(), nil
}
