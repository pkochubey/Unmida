package main

import (
	"unmida/pkg/app"
	"os"
)

func main() { os.Exit(app.CLI(os.Args[1:])) }
