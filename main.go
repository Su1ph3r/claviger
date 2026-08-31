package main

import (
	"fmt"
	"os"

	"github.com/Su1ph3r/claviger/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "claviger:", err)
		os.Exit(1)
	}
}
