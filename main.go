package main

import (
	"github.com/dutchcoders/spring4shell-scanner/cmd"
	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

func main() {
	cli.ErrWriter = color.Output

	app := cmd.New()
	app.RunAndExitOnError()
}
