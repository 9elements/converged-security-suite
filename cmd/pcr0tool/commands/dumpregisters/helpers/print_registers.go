package helpers

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/registers"
)

// PrintRegisters outputs registers in a detailed human-readable format
func PrintRegisters(regs registers.Registers) {
	for _, reg := range regs {
		fmt.Printf("\n")
		PrintRegister(reg)
	}
}

// PrintRegister outputs a single register in a detailed human-readable format
func PrintRegister(reg registers.Register) {
	fmt.Printf("Register: %s, address: 0x%X\n", reg.ID(), reg.Address())
	switch r := reg.(type) {
	case registers.RawRegister:
		for idx, b := range r.Raw() {
			if idx%8 == 0 {
				fmt.Printf("\n")
			}
			fmt.Printf("%X ", b)
		}
		fmt.Printf("\n")
	case registers.RawRegister8:
		fmt.Println("          1         0")
		fmt.Println("         109876543210")
		fmt.Printf("%08X %08b\n", r.Raw(), r.Raw())
	case registers.RawRegister16:
		fmt.Println("          2         1         0")
		fmt.Println("         1098765432109876543210")
		fmt.Printf("%08X %016b\n", r.Raw(), r.Raw())
	case registers.RawRegister32:
		fmt.Println("          3         2         1         0")
		fmt.Println("         10987654321098765432109876543210")
		fmt.Printf("%08X %032b\n", r.Raw(), r.Raw())
	case registers.RawRegister64:
		fmt.Println("                    6         5         4         3         2         1         0")
		fmt.Println("                 3210987654321098765432109876543210987654321098765432109876543210")
		fmt.Printf("%016X %064b\n", r.Raw(), r.Raw())
	default:
		panic(fmt.Sprintf("register %s doesn't support any of raw access interfaces", r.ID()))
	}

	var fieldsTotalSize uint8
	for _, field := range reg.Fields() {
		if len(field.Value) == 8 {
			fmt.Printf("\t%2d-%2d: %8X: %s\n", fieldsTotalSize, fieldsTotalSize+field.BitSize-1,
				registers.FieldValueToNumber(field.Value), field.Name)
		} else {
			fmt.Printf("\t%2d-%2d: %8X: %s\n", fieldsTotalSize, fieldsTotalSize+field.BitSize-1, field.Value, field.Name)
		}
		fieldsTotalSize += field.BitSize
	}
}
