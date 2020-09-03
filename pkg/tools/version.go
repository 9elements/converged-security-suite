package tools

import "fmt"

// ShowVersion shows progam version
func ShowVersion(toolName, tag, commit string) {
	fmt.Printf("%s %s\n", toolName, tag)
	fmt.Println("")
	fmt.Printf("Build Commit: %s\n", commit)
	fmt.Println("License: BSD 3-Clause License")
	fmt.Println("")
	fmt.Println("Copyright (c) 2020, 9elements GmbH.")
	fmt.Println("Copyright (c) 2020, facebook Inc.")
	fmt.Println("All rights reserved.")
}
