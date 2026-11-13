package main

import (
	"fmt"
	"strconv"
	"strings"
)

// flagSpec describes one option accepted by a command, getopt style.
type flagSpec struct {
	short    byte
	long     string
	optValue bool // accepts an optional numeric value: -c2, --clip=2
}

// parsedArgs holds the result of parseOptions.
type parsedArgs struct {
	flags      map[string]bool
	values     map[string]int
	positional []string
}

// parseOptions parses short (-r, -rf, -c2) and long (--recursive, --clip=2)
// options in any position. "--" ends option parsing.
func parseOptions(args []string, specs []flagSpec) (*parsedArgs, error) {
	res := &parsedArgs{flags: map[string]bool{}, values: map[string]int{}}
	optionsDone := false

	findShort := func(c byte) *flagSpec {
		for i := range specs {
			if specs[i].short == c {
				return &specs[i]
			}
		}
		return nil
	}
	setValue := func(spec *flagSpec, raw string) error {
		res.flags[spec.long] = true
		if raw == "" {
			return nil
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return fmt.Errorf("invalid value for --%s: %q", spec.long, raw)
		}
		res.values[spec.long] = n
		return nil
	}

	for _, a := range args {
		switch {
		case optionsDone || a == "-" || !strings.HasPrefix(a, "-"):
			res.positional = append(res.positional, a)
		case a == "--":
			optionsDone = true
		case strings.HasPrefix(a, "--"):
			name, value, hasValue := strings.Cut(a[2:], "=")
			var spec *flagSpec
			for i := range specs {
				if specs[i].long == name {
					spec = &specs[i]
					break
				}
			}
			if spec == nil {
				return nil, fmt.Errorf("unknown option: %s", a)
			}
			if hasValue && !spec.optValue {
				return nil, fmt.Errorf("option --%s does not take a value", name)
			}
			if err := setValue(spec, value); err != nil {
				return nil, err
			}
		default:
			for i := 1; i < len(a); i++ {
				spec := findShort(a[i])
				if spec == nil {
					return nil, fmt.Errorf("unknown option: -%c", a[i])
				}
				if spec.optValue {
					// The rest of the argument is the value, as in getopt (-c2)
					if err := setValue(spec, a[i+1:]); err != nil {
						return nil, err
					}
					break
				}
				res.flags[spec.long] = true
			}
		}
	}
	return res, nil
}
