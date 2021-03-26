package mathtools

// Max returns a maximal value (from the `int`-s passed as the arguments)
func Max(arg0 int, args ...int) int {
	result := arg0
	for _, arg := range args {
		if arg > result {
			result = arg
		}
	}

	return result
}

// UMax returns a maximal value (from the `uint`-s passed as the arguments)
func UMax(arg0 uint, args ...uint) uint {
	result := arg0
	for _, arg := range args {
		if arg > result {
			result = arg
		}
	}

	return result
}

// Min returns a minimal value (from the `int`-s passed as the arguments)
func Min(arg0 int, args ...int) int {
	result := arg0
	for _, arg := range args {
		if arg < result {
			result = arg
		}
	}

	return result
}
