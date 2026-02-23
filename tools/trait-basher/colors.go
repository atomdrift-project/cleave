package main

// ANSI color codes for terminal output.
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
)

// providerColor returns the color code for a given provider name.
func providerColor(provider string) string {
	switch provider {
	case "claude":
		return colorMagenta
	case "gemini":
		return colorBlue
	case "codex":
		return colorGreen
	case "ollama":
		return colorYellow
	default:
		return colorCyan
	}
}

// rateColor returns a color based on the rate percentage.
// Green for high rates (good), yellow for medium, red for low.
func rateColor(rate float64) string {
	switch {
	case rate >= 90:
		return colorGreen
	case rate >= 70:
		return colorYellow
	default:
		return colorRed
	}
}

// critColor returns the color for a criticality level.
func critColor(crit string) string {
	switch crit {
	case "hostile":
		return colorRed
	case "suspicious":
		return colorYellow
	case "notable":
		return colorCyan
	default:
		return colorDim
	}
}
