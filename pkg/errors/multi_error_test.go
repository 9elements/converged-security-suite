package errors

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMultiErrorMarshalJSON(t *testing.T) {
	mErr := MultiError{errors.New("simple error message"), errors.New(`I am a citizen of "Earth"!`)}
	b, err := mErr.MarshalJSON()
	require.NoError(t, err)
	var errDescr string
	err = json.Unmarshal(b, &errDescr)
	require.NoError(t, err, string(b))
	require.Equal(t, `"errors: simple error message; I am a citizen of \"Earth\"!"`, string(b))
}
