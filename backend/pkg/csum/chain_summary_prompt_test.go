package csum

import (
	"strings"
	"testing"
)

func TestSummarizationInstructions_AreCompactAndFocused(t *testing.T) {
	t.Parallel()

	instructions := getSummarizationInstructions(1)

	if len(instructions) > 1200 {
		t.Fatalf("instructions are too long: got %d chars, want <= 1200", len(instructions))
	}

	forbidden := []string{
		"PRESERVE ALL technical details",
		"Maintain complete code examples",
		"HANDLING PREVIOUSLY SUMMARIZED CONTENT:",
		"KEY REQUIREMENTS:",
	}
	for _, phrase := range forbidden {
		if strings.Contains(instructions, phrase) {
			t.Fatalf("instructions should not contain %q", phrase)
		}
	}

	required := []string{
		"commands, parameters, errors, results",
		"Do not summarize the context itself",
		"follow the problem-solution flow",
	}
	for _, phrase := range required {
		if !strings.Contains(instructions, phrase) {
			t.Fatalf("instructions should contain %q", phrase)
		}
	}
}
