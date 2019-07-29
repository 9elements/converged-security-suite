package gomsr

import (
	"os/exec"
	"testing"
)

func Test_ReadMSR(t *testing.T) {

	//yah, this is...super lazy.
	out, err := exec.Command("sh", "-c",
		"echo '12345678' >> /tmp/msr_test0.txt").Output()

	if err != nil {
		t.Fatalf("Error in cmd: %s, %s", err, out)
	}

	fd, err := ReadMSRWithLocation(0, 0, "/tmp/msr_test%d.txt")
	if err != nil {
		t.Fatalf("Error: %s", err)
	}

	if fd != 4050765991979987505 {
		t.Fatalf("Error, bad return: %s", err)
	}

	out, err = exec.Command("rm", "/tmp/msr_test0.txt").Output()

	if err != nil {
		t.Fatalf("Error in cmd: %s, %s", err, out)
	}
}

func Test_writeMSR(t *testing.T) {
	out, err := exec.Command("touch", "/tmp/msr_write0.txt").Output()

	if err != nil {
		t.Fatalf("Error in cmd: %s, %s", err, out)
	}

	err = WriteMSRWithLocation(0, 0, 0xff, "/tmp/msr_write%d.txt")
	if err != nil {
		t.Fatalf("Error in write: %s", err)
	}

	dat, err := ReadMSRWithLocation(0, 0, "/tmp/msr_write%d.txt")
	if err != nil {
		t.Fatalf("Error: %s", err)
	}

	if dat != 0xff {
		t.Fatalf("Error, bad return: 0x%x", dat)
	}

	out, err = exec.Command("rm", "/tmp/msr_write0.txt").Output()

	if err != nil {
		t.Fatalf("Error in cmd: %s, %s", err, out)
	}

}

// func Test_ReadMSRReal(t *testing.T) {
// 	fd, err := ReadMSR(0, 0x198)
// 	if err != nil {
// 		t.Fatalf("Error: %s", err)
// 	}

// 	fmt.Printf("Got 0x%x\n", fd)
// }
