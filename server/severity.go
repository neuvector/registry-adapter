package server

import (
	"os"
	"strconv"
	"strings"
)

// Controls whether severity is determined based on NeuVector's vulnerability feed ratings.
// Set the environment variable USE_FEED_BASED_SEVERITY to "true" to enable this behavior.
var useFeedBasedSeverity, _ = strconv.ParseBool(os.Getenv("USE_FEED_BASED_SEVERITY"))

// computeOverallSeverity returns the highest severity found in the vulnerability list
func computeOverallSeverity(vulns []Vuln) string {
	severityOrder := map[string]int{
		"Critical":   5,
		"High":       4,
		"Medium":     3,
		"Low":        2,
		"Negligible": 1,
		"Unknown":    0,
	}
	maxSeverity := "Unknown"
	maxLevel := 0

	for _, v := range vulns {
		if level, ok := severityOrder[v.Severity]; ok && level > maxLevel {
			maxLevel = level
			maxSeverity = v.Severity
		}
	}
	return maxSeverity
}

// cvssScoreToSeverity maps CVSS score to Harbor severity levels
func cvssScoreToSeverity(score float32) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score > 0:
		return "Low"
	case score == 0:
		return "Negligible" // Negligible = "None" in Harbor CVSS3 severity.
	default:
		return "Unknown"
	}
}

func mapFeedRatingToSeverity(feedRating string, cvssScore float32) string {
	// Normalize feed rating to lowercase for comparison
	switch strings.ToLower(feedRating) {
	case "critical":
		return "Critical"
	case "important", "high":
		return "High"
	case "medium", "moderate":
		return "Medium"
	case "low", "unimportant", "negligible", "end-of-life": // return negligible as low, since the cve is theoritically still something.
		return "Low"
	case "none":
		return "Negligible" // return None as Negligible, since Negligible = "None" in Harbor CVSS3 severity.
	default:
		// "", "unknown", "untriaged", "not yet assigned" etc. will be catched in default case, we want to show them.
		// If we give this case "Unknown", it's easly overlooked while it still can be a serious vulnerability.
		return cvssScoreToSeverity(cvssScore)
	}
}
