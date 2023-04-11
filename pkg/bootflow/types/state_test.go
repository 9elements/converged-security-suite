package types

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/bxcodec/faker"
	"github.com/hashicorp/go-multierror"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/stretchr/testify/require"
)

type fakeSystemArtifact struct{}

func (sa *fakeSystemArtifact) Size() uint64 {
	return 1
}

func (sa *fakeSystemArtifact) ReadAt(p []byte, off int64) (n int, err error) {
	return 0, fmt.Errorf("unit-test: not implemented")
}

var _ SystemArtifact = (*fakeSystemArtifact)(nil)

type fakeSubSystem struct{}

func (ss *fakeSubSystem) IsInitialized() bool {
	return true
}

var _ SubSystem = (*fakeSubSystem)(nil)

type fakeActor struct{}

var _ Actor = (*fakeActor)(nil)

func (a *fakeActor) ResponsibleCode() DataSource {
	return nil
}

type fakeAction struct{}

var _ Action = (*fakeAction)(nil)

func (a *fakeAction) Apply(context.Context, *State) error {
	return nil
}

type fakeStep struct{}

var _ Step = (*fakeStep)(nil)

func (s *fakeStep) Actions(context.Context, *State) Actions {
	return nil
}

type fakeAddressMapper struct{}

var _ AddressMapper = (*fakeAddressMapper)(nil)

func (am *fakeAddressMapper) Resolve(sa SystemArtifact, ranges ...pkgbytes.Range) (pkgbytes.Ranges, error) {
	return ranges, nil
}
func (am *fakeAddressMapper) Unresolve(sa SystemArtifact, ranges ...pkgbytes.Range) (pkgbytes.Ranges, error) {
	return ranges, nil
}

type fakeDataConverter struct{}

var _ DataConverter = (*fakeDataConverter)(nil)

func (dc *fakeDataConverter) Convert(b RawBytes) ConvertedBytes {
	return ConvertedBytes(b)
}

type fakeDataConverterFactory struct{}

var _ DataConverterFactory = (*fakeDataConverterFactory)(nil)

func (dc *fakeDataConverterFactory) NewDataConverter() DataConverter {
	return (*fakeDataConverter)(nil)
}

type fakeDataSource struct{}

var _ DataSource = (*fakeDataSource)(nil)

func (ds *fakeDataSource) Data(context.Context, *State) (*Data, error) {
	return &Data{}, nil
}

func init() {
	var errors *multierror.Error

	systemArtifact := (*fakeSystemArtifact)(nil)
	errors = multierror.Append(errors,
		faker.AddProvider("system_artifact", func(v reflect.Value) (interface{}, error) {
			return systemArtifact, nil
		}),

		faker.AddProvider("system_artifact_map", func(v reflect.Value) (interface{}, error) {
			return map[reflect.Type]SystemArtifact{
				reflect.ValueOf(systemArtifact).Type(): systemArtifact,
			}, nil
		}),
		faker.AddProvider("address_mapper", func(v reflect.Value) (interface{}, error) {
			return (*fakeAddressMapper)(nil), nil
		}),
		faker.AddProvider("data_converter", func(v reflect.Value) (interface{}, error) {
			return (*fakeDataConverter)(nil), nil
		}),
		faker.AddProvider("data_converter_factory", func(v reflect.Value) (interface{}, error) {
			return (*fakeDataConverterFactory)(nil), nil
		}),
		faker.AddProvider("data_source", func(v reflect.Value) (interface{}, error) {
			return (*fakeDataSource)(nil), nil
		}),
		faker.AddProvider("sub_system_map", func(v reflect.Value) (interface{}, error) {
			return map[reflect.Type]SubSystem{
				reflect.ValueOf((*fakeSubSystem)(nil)).Type(): (*fakeSubSystem)(nil),
			}, nil
		}),
		faker.AddProvider("trust_chain", func(v reflect.Value) (interface{}, error) {
			return (*fakeSubSystem)(nil), nil
		}),
		faker.AddProvider("actor", func(v reflect.Value) (interface{}, error) {
			return (*fakeActor)(nil), nil
		}),
		faker.AddProvider("action", func(v reflect.Value) (interface{}, error) {
			return (*fakeAction)(nil), nil
		}),
		faker.AddProvider("step", func(v reflect.Value) (interface{}, error) {
			return (*fakeStep)(nil), nil
		}),
		faker.AddProvider("flow", func(v reflect.Value) (interface{}, error) {
			return Flow{Name: "fakeFLow", Steps: Steps{(*fakeStep)(nil)}}, nil
		}),
	)

	if err := errors.ErrorOrNil(); err != nil {
		panic(err)
	}
}

func TestStateReset(t *testing.T) {
	s := NewState()
	err := faker.FakeData(s)
	require.NoError(t, err)

	s.Reset()
	if len(s.MeasuredData) == 0 {
		s.MeasuredData = nil
	}

	require.Equal(t, NewState(), s)
}
