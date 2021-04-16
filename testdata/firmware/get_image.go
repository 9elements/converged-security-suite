package firmware

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/ulikunitz/xz"
)

func GetTestImage(testImagePath string) ([]byte, error) {
	xzFile, err := os.Open(testImagePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file '%s': %w", testImagePath, err)
	}

	r, err := xz.NewReader(xzFile)
	if err != nil {
		return nil, fmt.Errorf("unable to start decompressing file '%s': %w", testImagePath, err)
	}

	img, err := ioutil.ReadAll(r)
	if err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("unable to decompress file '%s': %w", testImagePath, err)
		}
	}

	return img, nil
}
