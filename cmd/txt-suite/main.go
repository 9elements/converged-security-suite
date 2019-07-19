package main

import (
	"flag"
	"fmt"

	"github.com/9elements/txt-suite/pkg/test"
)

var (
	testnos []int
	testerg bool
)

func run() {
	if len(testnos) != 0 {
		for _, item := range testnos {
			if item <= len(test.TestsCPU) {
				testerg = test.TestsCPU[item-1].Run()
			} else if item <= len(test.TestsCPU)+len(test.TestsTPM) {
				testerg = test.TestsTPM[item-len(test.TestsCPU)-1].Run()
			} else if item <= len(test.TestsCPU)+len(test.TestsTPM)+len(test.TestsFIT) {
				testerg = test.TestsCPU[item-len(test.TestsCPU)-len(test.TestsTPM)-1].Run()
			} else if item <= len(test.TestsCPU)+len(test.TestsTPM)+len(test.TestsFIT)+len(test.TestsMemory) {
				testerg = test.TestsMemory[item-len(test.TestsCPU)-len(test.TestsTPM)-len(test.TestsFIT)-1].Run()
			} else {
				fmt.Printf("Testnumber not valid. Pick from 1 up to 51.\n")
			}
			if testerg == false && stayAlive() == false {
				fmt.Println("Abord testing due to error occurrence")
				return
			}
		}
	} else {
		for _, t := range test.TestsCPU {
			if !t.Run() && t.Required {
				return
			}
		}

		for _, t := range test.TestsTPM {
			if !t.Run() && t.Required {
				return
			}
		}

		for _, t := range test.TestsFIT {
			if !t.Run() && t.Required {
				return
			}
		}

		for _, t := range test.TestsMemory {
			if !t.Run() && t.Required {
				return
			}
		}
	}

}

func main() {
	//var tmp []int
	flag.Parse()

	if flagUsed() == true {
		testnos, _ = deconstructFlag()
	}

	if !*help && !*listtests {
		err := test.ConnectTPM("/dev/tpm0")
		if err != nil {
			fmt.Printf("Cannot connect to TPM: %s\n", err)
			return
		}

		err = test.LoadFITFromMemory()
		if err != nil {
			fmt.Printf("Cannot load FIT from memory: %s\n", err)
			return
		}

		run()
	} else {
		if *listtests == true {
			listTests()
		}
		if *help == true {
			showHelp()
		}
	}

}
