package server

import (
	"testing"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
)

func TestMapFeedRatingToSeverity(t *testing.T) {
	tests := []struct {
		name       string
		feedRating string
		cvssScore  float32
		expected   string
	}{
		{"Critical", "critical", 5.0, "Critical"},
		{"Important", "important", 5.0, "High"},
		{"High", "high", 5.0, "High"},
		{"Medium", "medium", 5.0, "Medium"},
		{"Moderate", "moderate", 5.0, "Medium"},
		{"Low", "low", 5.0, "Low"},
		{"None", "none", 5.0, "None"},
		{"Unimportant", "unimportant", 5.0, "Low"},
		{"Negligible", "negligible", 5.0, "Low"},
		{"End-of-life", "end-of-life", 5.0, "Low"},
		{"Unknown", "unknown", 5.0, "Low"},
		{"", "", 9.5, "Critical"},
		{"", "", 7.5, "High"},
		{"", "", 4.5, "Medium"},
		{"", "", 1.5, "Low"},
		{"", "", 0, "None"},
		{"Unexpected", "unexpected", 6.5, "Medium"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapFeedRatingToSeverity(tt.feedRating, tt.cvssScore)
			require.Equal(t, tt.expected, result, "feed rating mapping mismatch")
		})
	}
}

func TestCvssScoreToSeverity(t *testing.T) {
	tests := []struct {
		name     string
		score    float32
		expected string
	}{
		{"Critical", 9.0, "Critical"},
		{"High", 7.0, "High"},
		{"Medium", 4.0, "Medium"},
		{"Low", 1.0, "Low"},
		{"Negligible", 0.0, "Negligible"},
		{"Unknown", -1.0, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cvssScoreToSeverity(tt.score)
			require.Equal(t, tt.expected, result, "CVSS score mapping mismatch")
		})
	}
}

func TestComputeOverallSeverity(t *testing.T) {
	vulns := []Vuln{
		{Severity: "Low"},
		{Severity: "Medium"},
		{Severity: "High"},
		{Severity: "Unknown"},
	}

	expected := "High"
	result := computeOverallSeverity(vulns)
	require.Equal(t, expected, result, "overall severity mismatch")
}

func TestConvertVulns_FeedBasedEnabled(t *testing.T) {
	orig := useFeedBasedSeverity
	useFeedBasedSeverity = true
	defer func() { useFeedBasedSeverity = orig }()

	controllerVulns := []*share.ScanVulnerability{
		{
			Name:           "CVE-2021-1234",
			PackageName:    "test-pkg",
			PackageVersion: "1.0.0",
			FixedVersion:   "1.0.1",
			FeedRating:     "high",
			Description:    "Test description",
			Link:           "http://example.com",
			Score:          5.5,
			ScoreV3:        7.2,
			Vectors:        "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
			VectorsV3:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		},
	}

	vulns := convertVulns(controllerVulns)
	require.Len(t, vulns, 1, "expected 1 vulnerability")

	v := vulns[0]
	require.Equal(t, "High", v.Severity, "severity mismatch")
	require.Equal(t, "CVE-2021-1234", v.ID, "ID mismatch")
	require.Equal(t, "test-pkg", v.Pkg, "package mismatch")
	require.Equal(t, "1.0.0", v.Version, "version mismatch")
	require.Equal(t, "1.0.1", v.FixVersion, "fix version mismatch")
	require.Equal(t, "Test description", v.Description, "description mismatch")
	require.Len(t, v.Links, 1, "expected 1 link")
	require.Equal(t, "http://example.com", v.Links[0], "link mismatch")
	require.Equal(t, float32(7.2), v.PreferredCVSS.ScoreV3, "CVSSv3 score mismatch")
	require.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", v.PreferredCVSS.VectorV3, "CVSSv3 vector mismatch")
}

func TestConvertVulns_FeedBasedDisabled(t *testing.T) {
	orig := useFeedBasedSeverity
	useFeedBasedSeverity = false
	defer func() { useFeedBasedSeverity = orig }()

	controllerVulns := []*share.ScanVulnerability{
		{
			Name:           "CVE-2021-1234",
			PackageName:    "test-pkg",
			PackageVersion: "1.0.0",
			FixedVersion:   "1.0.1",
			Severity:       "Medium",
			Description:    "Test description",
			Link:           "http://example.com",
			Score:          5.5,
			ScoreV3:        7.2,
			Vectors:        "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
			VectorsV3:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		},
	}

	vulns := convertVulns(controllerVulns)
	require.Len(t, vulns, 1, "expected 1 vulnerability")

	v := vulns[0]
	require.Equal(t, "Medium", v.Severity, "severity mismatch")
}

func TestConvertRPCReportToScanReport(t *testing.T) {
	scanResult := &share.ScanResult{
		Vuls: []*share.ScanVulnerability{
			{
				Name:           "CVE-2021-1234",
				PackageName:    "test-pkg",
				PackageVersion: "1.0.0",
				FixedVersion:   "1.0.1",
				Severity:       "High",
				Description:    "Test description",
				Link:           "http://example.com",
				Score:          5.5,
				ScoreV3:        7.2,
				Vectors:        "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
				VectorsV3:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			},
		},
	}

	report := convertRPCReportToScanReport(scanResult)
	require.Equal(t, 200, report.Status, "status mismatch")
	require.Equal(t, "High", report.Severity, "overall severity mismatch")
	require.Len(t, report.Vulnerabilities, 1, "expected 1 vulnerability")
}

func TestGenerateExpirationTime(t *testing.T) {
	now := time.Now().UTC()
	expiration := generateExpirationTime()
	expected := now.Add(expirationTime)

	require.WithinDuration(t, expected, expiration, time.Second, "expiration time mismatch")
}