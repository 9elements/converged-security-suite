package acm

import (
	"encoding/json"
	"os"

	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
	"github.com/tidwall/pretty"
)

func ReadACM(filepath string) (*fit.EntrySACMData3, error) {
	var acm fit.EntrySACMData3
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &acm); err != nil {
		return nil, err
	}
	return &acm, nil
}

func WriteACM(f *os.File, acm *fit.EntrySACMData3) error {
	cfg, err := json.Marshal(acm)
	if err != nil {
		return err
	}
	json := pretty.Pretty(cfg)
	if _, err := f.Write(json); err != nil {
		return err
	}
	return nil
}
