package azcfg

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/KarlGW/azcfg/azure/cloud"
)

// coelesceString returns the first non-empty string (if any).
func coalesceString(x, y string) string {
	if len(x) > 0 {
		return x
	}
	return y
}

// coalesceMap returns the first non-empty map (if any).
func coalesceMap[K comparable, V any](x, y map[K]V) map[K]V {
	if len(x) > 0 {
		return x
	}
	return y
}

// parseBool returns the boolean represented by the string.
// If the string cannot be parsed, it returns false.
func parseBool(s string) bool {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false
	}
	return b
}

// parseLabels from the provided string. Format: setting1=label1,setting2=label2.
func parseLabels(labels string) map[string]string {
	if len(labels) == 0 {
		return nil
	}

	re := regexp.MustCompile(`\s+`)
	parts := strings.Split(re.ReplaceAllString(labels, ""), ",")
	m := make(map[string]string, len(parts))
	for i := range parts {
		p := strings.Split(parts[i], "=")
		if len(p) == 2 {
			m[p[0]] = p[1]
		}

	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// parseCloud returns the cloud from the provided string.
func parseCloud(c string) cloud.Cloud {
	switch strings.ToLower(c) {
	case "azure", "public", "azurepublic":
		return cloud.AzurePublic
	case "government", "azuregovernment":
		return cloud.AzureGovernment
	case "china", "azurechina":
		return cloud.AzureChina
	default:
		return cloud.AzurePublic
	}
}
