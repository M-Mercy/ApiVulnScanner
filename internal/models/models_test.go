package models

import (
	"testing"
	"time"
)

func TestSeverityScore(t *testing.T) {
	tests := []struct {
		severity Severity
		want     int
	}{
		{SeverityCritical, 5},
		{SeverityHigh, 4},
		{SeverityMedium, 3},
		{SeverityLow, 2},
		{SeverityInformational, 1},
		{Severity("UNKNOWN"), 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := tt.severity.Score()
			if got != tt.want {
				t.Errorf("Severity(%s).Score() = %d, want %d", tt.severity, got, tt.want)
			}
		})
	}
}

func TestEndpointString(t *testing.T) {
	endpoint := &Endpoint{
		URL:    "https://api.example.com/v1/users",
		Method: MethodGET,
	}

	want := "GET https://api.example.com/v1/users"
	got := endpoint.String()

	if got != want {
		t.Errorf("Endpoint.String() = %q, want %q", got, want)
	}
}

func TestScanResultBuildSummary(t *testing.T) {
	now := time.Now()
	result := &ScanResult{
		ID:        "test-id",
		StartedAt: now,
		Findings: []*Finding{
			{Severity: SeverityCritical},
			{Severity: SeverityCritical},
			{Severity: SeverityHigh},
			{Severity: SeverityMedium},
			{Severity: SeverityLow},
			{Severity: SeverityInformational},
		},
		Endpoints: []*Endpoint{
			{URL: "https://api.example.com/v1/users", Method: MethodGET},
			{URL: "https://api.example.com/v1/accounts", Method: MethodGET},
		},
	}

	result.BuildSummary()

	if result.Summary.TotalFindings != 6 {
		t.Errorf("TotalFindings = %d, want 6", result.Summary.TotalFindings)
	}
	if result.Summary.Critical != 2 {
		t.Errorf("Critical = %d, want 2", result.Summary.Critical)
	}
	if result.Summary.High != 1 {
		t.Errorf("High = %d, want 1", result.Summary.High)
	}
	if result.Summary.Medium != 1 {
		t.Errorf("Medium = %d, want 1", result.Summary.Medium)
	}
	if result.Summary.Low != 1 {
		t.Errorf("Low = %d, want 1", result.Summary.Low)
	}
	if result.Summary.Informational != 1 {
		t.Errorf("Informational = %d, want 1", result.Summary.Informational)
	}
	if result.Summary.TotalEndpoints != 2 {
		t.Errorf("TotalEndpoints = %d, want 2", result.Summary.TotalEndpoints)
	}
}
