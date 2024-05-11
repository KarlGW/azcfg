package azcfg

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/KarlGW/azcfg/azure/cloud"
)

// splitTrim splits a string by the provided separator, after
// trimming whitespaces.
func splitTrim(s, sep string) []string {
	if len(s) == 0 {
		return nil
	}
	if len(sep) == 0 {
		sep = ","
	}
	return strings.Split(regexp.MustCompile(`\s+`).ReplaceAllString(s, ""), sep)
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

// parseCSVKVP parses the provided comma-separated key-value pair string.
// Format: key1=value1,key2=value2.
func parseCSVKVP(csvkvp string) map[string]string {
	if len(csvkvp) == 0 {
		return nil
	}

	parts := splitTrim(csvkvp, ",")
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
