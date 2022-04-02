package cmd

import (
	"fmt"

	dirbuster "github.com/dutchcoders/spring4shell-scanner/app"
	build "github.com/dutchcoders/spring4shell-scanner/build"
	"github.com/fatih/color"
	logging "github.com/op/go-logging"

	cli "github.com/urfave/cli/v2"
)

var log = logging.MustGetLogger("dirbuster/cmd")

var globalFlags = []cli.Flag{
	&cli.StringSliceFlag{
		Name:  "targets",
		Usage: "",
		Value: cli.NewStringSlice(),
	},
	&cli.StringSliceFlag{
		Name:  "exclude",
		Usage: "exclude the following file paths (glob)",
		Value: cli.NewStringSlice(),
	},
	&cli.StringSliceFlag{
		Name:  "allow",
		Usage: "the non-vulnerable library hashes ",
		Value: cli.NewStringSlice(
			// spring beans 5.3.18
			"e962d99bf7b3753cded86ce8ce6b4be5bed27d0b59feeb2a85948e29bba2807d",
			// spring beans 5.2.20
			"ab242fb119664df49c64c8af8cfb1932446bdc342d3a56453e34f40fa860f0f4",
			// spring cloud function context 3.2.3
			"52c6ae60681d0869888720c83684c6e2d7017ebc399e7794427c2cbdc0c47d72",
		),
	},
	&cli.StringFlag{
		Name:  "logfile",
		Usage: "output to following file path (string)",
		Value: "./spring4shell.log",
	},
	&cli.BoolFlag{
		Name:  "disable-color",
		Usage: "disable color output",
	},
	&cli.IntFlag{
		Name:  "num-threads",
		Usage: "the number of threads to use",
		Value: 10,
	},
	&cli.BoolFlag{
		Name:  "dry",
		Usage: "enable dry run mode",
	},
	&cli.BoolFlag{
		Name:  "verbose",
		Usage: "enable verbose mode",
	},
	&cli.BoolFlag{
		Name:  "debug",
		Usage: "enable debug mode",
	},
	&cli.BoolFlag{
		Name:  "json",
		Usage: "output json",
	},
}

type Cmd struct {
	*cli.App
}

func ScanImageAction(c *cli.Context) error {
	options := []dirbuster.OptionFn{}

	if targets := c.StringSlice("targets"); len(targets) == 0 {
	} else if fn, err := dirbuster.TargetPaths(targets); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	if !c.Bool("dry") {
	} else if fn, err := dirbuster.Dry(); err != nil {
	} else {
		options = append(options, fn)
	}

	if !c.Bool("debug") {
	} else if fn, err := dirbuster.Debug(); err != nil {
	} else {
		options = append(options, fn)
	}

	if !c.Bool("verbose") {
	} else if fn, err := dirbuster.Verbose(); err != nil {
	} else {
		options = append(options, fn)
	}

	if allowList := c.StringSlice("allow"); len(allowList) == 0 {
	} else if fn, err := dirbuster.AllowList(allowList); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	if args := c.Args(); !args.Present() {
	} else if fn, err := dirbuster.TargetPaths(args.Slice()); err != nil { //|| fn.Host == "" {
		ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	b, err := dirbuster.New(options...)
	if err != nil {
		ec := cli.NewExitError(color.RedString("[!] Error: %s", err.Error()), 1)
		return ec
	}

	if err := b.ScanImage(c); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Error identifying application: %s", err.Error()), 1)
		return ec
	}

	return nil
}

func PatchAction(c *cli.Context) error {
	options := []dirbuster.OptionFn{}

	if targets := c.StringSlice("targets"); len(targets) == 0 {
	} else if fn, err := dirbuster.TargetPaths(targets); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	if !c.Bool("dry") {
	} else if fn, err := dirbuster.Dry(); err != nil {
	} else {
		options = append(options, fn)
	}

	if !c.Bool("debug") {
	} else if fn, err := dirbuster.Debug(); err != nil {
	} else {
		options = append(options, fn)
	}

	if !c.Bool("verbose") {
	} else if fn, err := dirbuster.Verbose(); err != nil {
	} else {
		options = append(options, fn)
	}

	if allowList := c.StringSlice("allow"); len(allowList) == 0 {
	} else if fn, err := dirbuster.AllowList(allowList); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	if args := c.Args(); !args.Present() {
	} else if fn, err := dirbuster.TargetPaths(args.Slice()); err != nil { //|| fn.Host == "" {
		ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	b, err := dirbuster.New(options...)
	if err != nil {
		ec := cli.NewExitError(color.RedString("[!] Error: %s", err.Error()), 1)
		return ec
	}

	if err := b.Patch(c); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Error identifying application: %s", err.Error()), 1)
		return ec
	}

	return nil
}

func ScanAction(c *cli.Context) error {
	options := []dirbuster.OptionFn{}

	v := c.Int("num-threads")
	if fn, err := dirbuster.NumThreads(v); err != nil {
		ec := cli.NewExitError(color.RedString(err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	if targets := c.StringSlice("targets"); len(targets) == 0 {
	} else if fn, err := dirbuster.TargetPaths(targets); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	if exclude := c.StringSlice("exclude"); len(exclude) == 0 {
	} else if fn, err := dirbuster.ExcludeList(exclude); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Could not set exclude list: %s", err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	if logfile := c.String("logfile"); len(logfile) == 0 {
	} else if fn, err := dirbuster.LogFile(logfile); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Could not set logfile: %s", err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	if allowList := c.StringSlice("allow"); len(allowList) == 0 {
	} else if fn, err := dirbuster.AllowList(allowList); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	if !c.Bool("dry") {
	} else if fn, err := dirbuster.Dry(); err != nil {
	} else {
		options = append(options, fn)
	}

	if !c.Bool("debug") {
	} else if fn, err := dirbuster.Debug(); err != nil {
	} else {
		options = append(options, fn)
	}

	if !c.Bool("verbose") {
	} else if fn, err := dirbuster.Verbose(); err != nil {
	} else {
		options = append(options, fn)
	}

	if args := c.Args(); !args.Present() {
	} else if fn, err := dirbuster.TargetPaths(args.Slice()); err != nil { //|| fn.Host == "" {
		ec := cli.NewExitError(color.RedString("[!] Could not set targets: %s", err.Error()), 1)
		return ec
	} else {
		options = append(options, fn)
	}

	b, err := dirbuster.New(options...)
	if err != nil {
		ec := cli.NewExitError(color.RedString("[!] Error: %s", err.Error()), 1)
		return ec
	}

	if err := b.Scan(c); err != nil {
		ec := cli.NewExitError(color.RedString("[!] Error identifying application: %s", err.Error()), 1)
		return ec
	}

	return nil
}
func New() *Cmd {
	app := cli.NewApp()
	app.Name = "spring4shell-scanner"
	app.Copyright = "All rights reserved Remco Verhoef [DTACT]"
	app.Authors = []*cli.Author{
		{
			Name:  "Remco Verhoef",
			Email: "remco.verhoef@dtact.com",
		}}
	app.Description = `This application will scan recursively through archives to detect spring-beans libraries and the CachedIntrospectionResults.class class files.`
	app.Flags = globalFlags
	app.Commands = []*cli.Command{
		{
			Name:   "scan",
			Action: ScanAction,
		},
		{
			Name:   "scan-image",
			Action: ScanImageAction,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "local",
					Usage: "scan local images",
				},
			},
		},
	}

	app.Version = fmt.Sprintf("%s (build on %s)", build.ReleaseTag, build.BuildDate)
	app.Before = func(c *cli.Context) error {
		fmt.Println("spring4shell-scanner by DTACT")
		fmt.Println("http://github.com/dtact/spring4shell-scanner")
		fmt.Println("--------------------------------------")

		color.NoColor = c.Bool("disable-color")
		return nil
	}

	app.Action = ScanAction
	return &Cmd{
		App: app,
	}
}
