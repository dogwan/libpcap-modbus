package main

/*
#cgo LDFLAGS: -lpcap
#cgo CFLAGS: -std=c11

#include "pkt.h"
*/
import "C"
import "errors"
import "fmt"
import "unsafe"

func listAllIfaces() error {
	C.listAllIfaces()

	return nil
}

func captureIface(args []string, cnt int) error {
	var argc = len(args)
	if argc == 0 {
		return errors.New("device is not provided.")
	}

	var device = C.CString(args[0])
	var filter *C.char = nil
	var count = C.int(cnt)

	if argc >= 2 {
		filter = C.CString(args[1])
	}

	C.captureIface(device, filter, count)

	return nil
}

//export HandlerWrap
func HandlerWrap(arr unsafe.Pointer, length C.int) {
	var bytes = C.GoBytes(arr, length)

	fmt.Println("len:", length)
	fmt.Print("[")
	for i := 0; i < len(bytes); i++ {
		fmt.Printf("%02x ", bytes[i])
	}
	fmt.Println("]")

	// fmt.Printf("dst: %02x-%02x-%02x-%02x-%02x-%02x", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
	// fmt.Print(" - ")
	// fmt.Printf("src: %02x-%02x-%02x-%02x-%02x-%02x\n", bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11])
}
