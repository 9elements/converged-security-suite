package main

import (
	"flag"
	"sort"
	"strconv"
	"strings"
)

var testno = flag.String("t", "", "Select test number 1 - 50. e.g.: -t 1,2,3,4,...")

func flagUsed() bool {
	return testno != nil
}

func deconstructFlag() ([]int, error) {
	var testnos []int
	tmpstrings := strings.Split(*testno, ",")
	for _, item := range tmpstrings {
		tmpno, err := strconv.Atoi(item)
		if err != nil {
			return nil, err
		}
		testnos = append(testnos, tmpno)
	}
	//Sort array
	sort.Ints(testnos)
	return testnos, nil

}
