package prober

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

type registryResult struct {
	Name        string
	LabelValues map[string]string
	Value       float64
}

func (rr *registryResult) String() string {
	var labels []string
	for k, v := range rr.LabelValues {
		labels = append(labels, k+"=\""+v+"\"")
	}
	m := rr.Name
	if len(labels) > 0 {
		m = fmt.Sprintf("%s{%s}", m, strings.Join(labels, ","))
	}
	return fmt.Sprintf("%s %f", m, rr.Value)
}

func checkRegistryResults(expRes *registryResult, mfs []*dto.MetricFamily, t *testing.T) {
	var results []*registryResult
	for _, mf := range mfs {
		for _, metric := range mf.Metric {
			labelValues := make(map[string]string)
			for _, l := range metric.GetLabel() {
				labelValues[l.GetName()] = l.GetValue()
			}
			results = append(results, &registryResult{
				Name:        mf.GetName(),
				LabelValues: labelValues,
				Value:       metric.GetGauge().GetValue(),
			})
		}
	}
	var ok bool
	var resStr string
	for _, res := range results {
		resStr = resStr + "\n" + res.String()
		if reflect.DeepEqual(res, expRes) {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("Expected %s, got: %s", expRes.String(), resStr)
	}
}
