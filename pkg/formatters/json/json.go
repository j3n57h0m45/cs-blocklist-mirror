package json

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/registry"
)

func Format(w http.ResponseWriter, r *http.Request) {
	decisions := r.Context().Value(registry.GlobalDecisionRegistry.Key).([]*models.Decision)
	var records []string
	for _, decision := range decisions {
		record := fmt.Sprintf(
			`{"Scope": "%s", "Value": "%s", "Scenario": "%s", "Duration": "%s"}`,
			*decision.Scope, formatDecisionValue(decision), *decision.Scenario, *decision.Duration)
		records = append(records, record)
	}
	response := fmt.Sprintf("[%s]", strings.Join(records, ","))
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, response)
}

func formatDecisionValue(decision *models.Decision) string {
	switch strings.ToLower(*decision.Scope) {
	case "ip":
		isIPv6 := strings.Contains(*decision.Value, ":")
		mask := 32 // Default value for IPv4
		if isIPv6 {
			mask = 64 // Update value for IPv6
		}
		return fmt.Sprintf("%s/%d", *decision.Value, mask)
	case "range":
		sep := strings.Split(*decision.Value, "/")
		return fmt.Sprintf("%s-%s", sep[0], sep[1])
	default:
		return *decision.Value
	}
}
