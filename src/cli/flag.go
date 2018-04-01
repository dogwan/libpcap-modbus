package main

import "flag"
import "errors"

type Arguments struct {
	Cmd    string
	CapCnt int
	Args   []string
}

func ParseArgs() Arguments {

	var arguments Arguments

	flag.IntVar(&arguments.CapCnt, "count", 0, "Number of packets to capture")

	flag.ErrHelp = errors.New(help())
	flag.Parse()

	arguments.Cmd = flag.Arg(0)
	if len(arguments.Cmd) == 0 {
		arguments.Cmd = "list"
	}

	if argc := len(flag.Args()) - 1; argc <= 0 {
		arguments.Args = make([]string, 0, 0)
	} else {
		var argv = flag.Args()
		arguments.Args = argv[1:]
	}

	return arguments
}

func help() string {
	return `
	usage: <command>

	commands:
	list																list all interfaces in device.
	cap [filter] {<option>}	<device> 		capture packet with provided filter.

	option:
	--count <num> 											Number of packets to capture.
	`
}
