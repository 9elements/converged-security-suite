package bootengine

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

type Step struct {
	Step         types.Step
	VerifiedData []types.VerifiedData
	Issues       StepIssues
}

type Log []Step

func (log Log) GoString() string {
	var result strings.Builder
	for idx, step := range log {
		fmt.Fprintf(&result, "%d. %#v:\n", idx, step.Step)
		if len(step.VerifiedData) > 0 {
			fmt.Fprintf(&result, "\tVerifiedData:\n")
			for idx, verifiedData := range step.VerifiedData {
				fmt.Fprintf(&result, "\t\t%d. %#v\n", idx, nestedGoStringOf(verifiedData))
			}
		}
		if len(step.Issues) > 0 {
			fmt.Fprintf(&result, "\tIssues:\n")
			for idx, issue := range step.Issues {
				fmt.Fprintf(&result, "\t\t%d. %#v\n", idx, nestedGoStringOf(issue))
			}
		}
	}
	return result.String()
}

func (log Log) GetVerifiedDataByTrustChainType(trustChainSample types.TrustChain) []types.VerifiedData {
	var result []types.VerifiedData
	cmpType := reducedType(trustChainSample)
	for _, step := range log {
		if len(step.VerifiedData) == 0 {
			continue
		}
		for _, verifiedData := range step.VerifiedData {
			if reducedType(verifiedData.TrustChain) == cmpType {
				result = append(result, verifiedData)
			}
		}
	}

	return result
}

func reducedType(i interface{}) reflect.Type {
	k := reflect.TypeOf(i)
	for k.Kind() == reflect.Ptr {
		k = k.Elem()
	}
	return k
}
