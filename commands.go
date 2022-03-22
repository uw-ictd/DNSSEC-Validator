package main

import (
	"github.com/urfave/cli/v2"
	"runtime"
)

var Commands = []*cli.Command{
	{
		Name:   "measure",
		Usage:  "Run a batch test and measurement job given a list of hostnames",
		Action: measure,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "inputlist",
				Aliases: []string{"i"},
				Value:   "test.csv",
				Usage:   "The path to the list of hostnames to run the measurement on",
			},
			&cli.StringFlag{
				Name:    "outdir",
				Aliases: []string{"o"},
				Value:   "results",
				Usage:   "Directory to save the output file along with the timestamp of the scan in <OutDir>/results-<Timestamp>.csv",
			},
			&cli.IntFlag{
				Name:    "parallelism",
				Aliases: []string{"p"},
				Value:   runtime.NumCPU() * 2,
				Usage:   "Number of workers to dispatch to complete measurement",
			},
		},
	},
	{
		Name:   "query",
		Usage:  "Run an individual test given a hostname",
		Action: singleMeasure,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "fqdn",
				Aliases: []string{"d"},
				Value:   "sudheesh.info.",
				Usage:   "The FQDN Hostname to check the DNSSEC Status",
			},
		},
	},
}
