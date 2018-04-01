package main

import "C"

func main() {
	var arg = ParseArgs()
	service(arg)
}

func service(arg Arguments) {
	var err error

	switch arg.Cmd {
	case "list":
		err = listAllIfaces()
	case "cap":
		err = captureIface(arg.Args, arg.CapCnt)
	}

	if err != nil {
		println(help())
	}
}