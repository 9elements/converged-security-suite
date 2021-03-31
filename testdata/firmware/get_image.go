package firmware

import (
	"fmt"
	"io"
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

	buf := make([]byte, 1<<23)
	n, err := r.Read(buf)
	if err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("unable to decompress file '%s': %w", testImagePath, err)
		}
	}

	return buf[:n], nil
}
