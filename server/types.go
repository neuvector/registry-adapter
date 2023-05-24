package server

import (
	"sync"
	"time"
)

type ScannerSpec struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type ReportData struct {
	sync.RWMutex
	ScanReports map[string]ScanReport
}

type QueueMap struct {
	sync.RWMutex
	Entries map[int]ScanRequest
}

type ScanReport struct {
	GeneratedAt     time.Time      `json:"generated_at"`
	Artifact        HarborArtifact `json:"artifact"`
	Scanner         ScannerSpec    `json:"scanner"`
	Severity        string         `json:"severity"`
	Vulnerabilities []Vuln         `json:"vulnerabilities"`
	Status          int
	ExpirationTime  time.Time
}

type CVSSDetails struct {
	ScoreV2  *float32 `json:"score_v2,omitempty"`
	ScoreV3  *float32 `json:"score_v3,omitempty"`
	VectorV2 string   `json:"vector_v2"`
	VectorV3 string   `json:"vector_v3"`
}

type Layer struct {
	Digest string `json:"digest,omitempty"`
	DiffID string `json:"diff_id,omitempty"`
}

type Vuln struct {
	ID               string                 `json:"id"`
	Pkg              string                 `json:"package"`
	Version          string                 `json:"version"`
	FixVersion       string                 `json:"fix_version,omitempty"`
	Severity         string                 `json:"severity"`
	Description      string                 `json:"description"`
	Links            []string               `json:"links"`
	Layer            *Layer                 `json:"layer"` // Not defined by Scanners API
	PreferredCVSS    *CVSSDetails           `json:"preferred_cvss,omitempty"`
	CweIDs           []string               `json:"cwe_ids,omitempty"`
	VendorAttributes map[string]interface{} `json:"vendor_attributes,omitempty"`
}

type ScannerAdapterMetadata struct {
	Scanner      ScannerSpec       `json:"scanner"`
	Capabilities []Capability      `json:"capabilities"`
	Properties   map[string]string `json:"properties"`
}

type ScanRequest struct {
	Registry      HarborRegistry `json:"registry"`
	Artifact      HarborArtifact `json:"artifact"`
	Authorization string
	WorkloadID    string
}

type HarborRegistry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

type HarborArtifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	MimeType   string `json:"mime_type,omitempty"`
	Tag        string `json:"tag"`
}

type ScanRequestReturn struct {
	ID string `json:"id"`
}

type Capability struct {
	ConsumeMIMEs []string `json:"consumes_mime_types"`
	ProduceMIMEs []string `json:"produces_mime_types"`
}
