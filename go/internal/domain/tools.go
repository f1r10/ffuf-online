package domain

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadToolRegistry reads the tool registry from path.
//
// When path is empty or the file cannot be read, a small built-in registry is
// returned and the error is reported through the second return value together
// with ok=false, so a missing file never crashes the API.
func LoadToolRegistry(path string) (tools []Tool, ok bool, err error) {
	if path == "" {
		return builtinTools(), false, nil
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		return builtinTools(), false, fmt.Errorf("tool registry %q unavailable: %w", path, readErr)
	}
	var entries []Tool
	if unmarshalErr := json.Unmarshal(raw, &entries); unmarshalErr != nil {
		return builtinTools(), false, fmt.Errorf("tool registry %q invalid: %w", path, unmarshalErr)
	}
	if len(entries) == 0 {
		return builtinTools(), false, fmt.Errorf("tool registry %q is empty", path)
	}
	return entries, true, nil
}

// builtinTools is the fallback registry used when the JSON file is absent. It
// deliberately mirrors the pinned entries of python/adapters/tool-registry.json.
func builtinTools() []Tool {
	return []Tool{
		{
			ToolID: "subfinder", Name: "Subfinder", Category: "reconnaissance", Version: "v2.6.6",
			Capabilities: []string{"subdomain_enumeration", "passive_recon"},
			RequiredInputs: []string{"domain"}, OutputTypes: []string{"subdomain"},
			SupportedAssetTypes: []string{"root_domain", "subdomain"},
			ApplicableExecutionProfiles: []string{"passive"},
			NetworkProfile: "passive_dns", Enabled: true, Priority: 9,
			Trigger: []string{"asset.discovered", "asset.updated"},
		},
		{
			ToolID: "dnsx", Name: "DNSx", Category: "reconnaissance", Version: "v1.2.1",
			Capabilities: []string{"dns_resolution", "dns_records"},
			RequiredInputs: []string{"hostname"}, OutputTypes: []string{"dns_record", "ip"},
			SupportedAssetTypes: []string{"hostname", "subdomain", "ip"},
			ApplicableExecutionProfiles: []string{"passive", "low_impact_discovery"},
			NetworkProfile: "dns", Enabled: true, Priority: 7,
			Trigger: []string{"asset.discovered", "asset.updated", "dns.record.discovered"},
		},
		{
			ToolID: "httpx", Name: "HTTPx", Category: "reconnaissance", Version: "v1.6.9",
			Capabilities: []string{"http_probe", "technology_detection", "title_extraction"},
			RequiredInputs: []string{"hostname"}, OutputTypes: []string{"http_service", "technology"},
			SupportedAssetTypes: []string{"hostname", "subdomain", "http_service"},
			ApplicableExecutionProfiles: []string{"low_impact_discovery"},
			NetworkProfile: "controlled_http", Enabled: true, Priority: 9,
			Trigger: []string{"asset.discovered", "dns.record.discovered"},
		},
		{
			ToolID: "nuclei", Name: "Nuclei", Category: "web_vulnerability_testing", Version: "v3.3.5",
			Capabilities: []string{"safe_vulnerability_templates", "technology_templates", "parameter_checks"},
			RequiredInputs: []string{"url"}, OutputTypes: []string{"finding"},
			SupportedAssetTypes: []string{"http_service", "endpoint", "technology"},
			ApplicableExecutionProfiles: []string{"low_impact_discovery", "authorized_vulnerability_testing"},
			NetworkProfile: "controlled_http", Enabled: true, Priority: 9,
			Trigger: []string{"http.service.discovered", "http.endpoint.discovered"},
		},
		{
			ToolID: "ffuf", Name: "FFUF", Category: "content_discovery", Version: "v2.1.0",
			Capabilities: []string{"directory_discovery", "file_discovery", "parameter_fuzzing"},
			RequiredInputs: []string{"url"}, OutputTypes: []string{"endpoint"},
			SupportedAssetTypes: []string{"http_service", "endpoint"},
			ApplicableExecutionProfiles: []string{"low_impact_discovery"},
			NetworkProfile: "controlled_http", Enabled: true, Priority: 7,
			Trigger: []string{"http.service.discovered"},
		},
	}
}

// ToolIndex returns the registry keyed by tool id.
func ToolIndex(tools []Tool) map[string]Tool {
	idx := make(map[string]Tool, len(tools))
	for _, t := range tools {
		idx[t.ToolID] = t
	}
	return idx
}
