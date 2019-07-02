package api

import (
	"encoding/json"
	"fmt"
	"strings"

	resty "gopkg.in/resty.v1"
)

const (
	arkIntelURL    = "https://odata.intel.com/API/v1_0/Products/Processors()?&$select=TXT&$filter=ProcessorNumber%20eq%20%27"
	arkIntelFormat = "%27&$format=json"
)

type intelMetadata struct {
	MetaData map[string]interface{} `json:"__metadata"`
	TXT      bool                   `json:"TXT"`
}

type intelData struct {
	Data []intelMetadata `json:"d"`
}

// ArchitectureTXTSupport
func ArchitectureTXTSupport() (bool, error) {
	cpuName := strings.Split(ProcessorBrandName(), " ")[3]
	resp, err := resty.R().Get(arkIntelURL + cpuName + arkIntelFormat)
	if err != nil || resp.StatusCode() != 200 {
		return false, err
	}

	var response intelData
	err = json.Unmarshal(resp.Body(), &response)
	if err != nil {
		return false, err
	}

	if len(response.Data) == 0 {
		return false, fmt.Errorf("No data\n")
	} else {
		return response.Data[0].TXT, nil
	}
}
