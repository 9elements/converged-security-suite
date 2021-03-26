package ostools

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/edsrzf/mmap-go"
)

// FileToBytes returns the contents of the file by path `filePath`.
func FileToBytes(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf(`unable to open the image-file "%v": %w`,
			filePath, err)
	}
	defer file.Close() // it was a read-only Open(), so we don't check the Close()

	// To consume less memory we use mmap() instead of reading the image
	// into the memory. However these bytes are also parsed by
	// linuxboot/fiano/pkg/uefi which consumes a lot of memory anyway :(
	//
	// See "man 2 mmap".
	contents, err := mmap.Map(file, mmap.RDONLY, 0)
	if err == nil {
		return contents, nil
	}

	// An error? OK, let's try the usual way to read data:
	contents, err = ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf(`unable to access data of the image-file "%v": %w`,
			filePath, err)
	}
	return contents, nil
}
