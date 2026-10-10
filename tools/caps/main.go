package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	lim := Limits{}
	flag.IntVar(&lim.FuncLines, "func", 40, "max lines in a function body (0: off)")
	flag.IntVar(&lim.FileLines, "file", 300, "max lines in a file (0: off)")
	flag.Parse()
	findings, err := checkDirs(flag.Args(), lim)
	if err != nil {
		fmt.Fprintln(os.Stderr, "caps:", err)
		os.Exit(2)
	}
	for _, f := range findings {
		fmt.Println(f)
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
}
