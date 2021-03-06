package main

import (
	"DNSSEC-Validator/resolver"
	"fmt"
	"github.com/miekg/dns"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"strings"
)

func query(hostname string, dnsQueryType uint16) ([]dns.RR, *resolver.AuthenticationChain, error) {
	rq, _ := resolver.NewResolver()
	result, chain, err := rq.StrictNSQuery(hostname, dnsQueryType)
	if err != nil {
		// Handle errors
		return nil, nil, err
	}
	return result, chain, nil
}

func worker(id int, rq *resolver.Resolver, records <-chan Record, results chan<- Record) {
	for r := range records {
		_, chain, err := rq.StrictNSQuery(r.Domain, dns.TypeA)
		if err != nil {
			results <- Record{Domain: r.Domain, DNSSECExists: false, DNSSECValid: false, reason: err.Error()}
		} else {
			if chain == nil {
				results <- Record{
					Domain:       r.Domain,
					DNSSECExists: true,
					DNSSECValid:  false,
					reason:       err.Error(),
				}
			} else {
				results <- Record{Domain: r.Domain, DNSSECExists: true, DNSSECValid: true, reason: ""}
			}
		}
	}
}

func performDNSSECMeasurement(records []Record, outBasePath string, workers int) {
	workerJobs := make(chan Record, len(records))
	workerJobResults := make(chan Record, len(records))

	measurementResults := make([]Record, len(records))

	rq, err := resolver.NewResolver()
	if err != nil {
		log.Fatalf("[ERROR] %v", err)
	}

	for w := 0; w < workers; w++ {
		go worker(w, rq, workerJobs, workerJobResults)
	}

	for _, r := range records {
		workerJobs <- r
	}

	for j := range measurementResults {
		result := <-workerJobResults
		measurementResults[j] = result
	}

	close(workerJobs)

	writeToDisk(measurementResults, outBasePath)
}

func measure(c *cli.Context) error {
	inputCsvPath := c.String("inputlist")
	outputCsvBaseDir := c.String("outdir")
	parallelismWorkers := c.Int("parallelism")

	records := readFormattedInput(inputCsvPath)
	performDNSSECMeasurement(records, outputCsvBaseDir, parallelismWorkers)
	return nil
}

func singleMeasure(c *cli.Context) error {
	fqdn := c.String("fqdn")
	res, chain, err := query(fqdn, dns.TypeA)
	if err != nil {
		return err
	}
	fmt.Printf("Valid DNS Record Answer for %v (%v)\n", fqdn, dns.TypeA)
	answer := res
	for _, a := range answer {
		fmt.Printf("%v\n", a)
	}
	fmt.Printf("containing the chain...\n")
	fmt.Printf("-----------------------CHAIN-----------------------\n")
	zones := chain.DelegationChain
	for i, sz := range zones {
		spaces := make([]string, 0)
		for k := 0; k < i*IndentSpace; k++ {
			spaces = append(spaces, " ")
		}
		spaceString := strings.Join(spaces, "")

		fmt.Printf("%v[Chain Level %v]\n", spaceString, i+1)
		fmt.Printf("%v\tZone      : %v\n", spaceString, sz.Zone)
		// DNSKEY Information
		fmt.Printf("%v\tDNSKEY    : (RRSET)\n", spaceString)
		rrset := sz.Dnskey.RrSet
		for _, s := range rrset {
			fmt.Printf("%v\t\t%v\n", spaceString, s.String())
		}
		fmt.Printf("%v\tDNSKEY    : (RRSIG)\n", spaceString)
		fmt.Printf("%v\t\t%v\n", spaceString, sz.Dnskey.RrSig)
		// DS Information
		dsset := sz.Ds.RrSet
		fmt.Printf("%v\tDS        : (RRSET)\n", spaceString)
		for _, s := range dsset {
			fmt.Printf("%v\t\t%v\n", spaceString, s.String())
		}
		fmt.Printf("%v\tDS        : (RRSIG)\n", spaceString)
		fmt.Printf("%v\t\t%v\n", spaceString, sz.Ds.RrSig)
		fmt.Printf("%v\tKeys      :\n", spaceString)
		for k, v := range sz.PubKeyLookup {
			fmt.Printf("%v\t\t %v : %v\n", spaceString, k, v)
		}
		fmt.Println("")
	}
	fmt.Printf("-------------------END CHAIN-----------------------\n")

	return nil
}

func main() {
	app := cli.App{
		Name:     "DNSSEC Validator",
		Usage:    "Validate a list of hostnames and their DNSSEC Status",
		Version:  Version,
		Commands: Commands,
		Authors: []*cli.Author{
			&cli.Author{
				Name:  "Sudheesh Singanamalla",
				Email: "sudheesh@cs.washington.edu",
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("[ERROR] %v\n", err)
	}
}
