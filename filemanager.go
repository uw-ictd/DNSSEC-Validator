package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

func readFormattedInput(path string) []Record {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("[ERROR] %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	records := make([]Record, 0)
	for scanner.Scan() {
		records = append(records, Record{
			Domain: fmt.Sprintf("%v.", scanner.Text()),
		})
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("[Scanner ERROR] %v", err)
	}
	return records
}

func writeToDisk(results []Record, dirPath string) {
	err := os.MkdirAll(dirPath, os.ModePerm)
	if err != nil {
		log.Fatalf("[ERROR] %v %v", err, dirPath)
	}
	filePath := fmt.Sprintf("%v/results-%v.csv", dirPath, time.Now().Unix())
	f, _ := os.Create(filePath)
	writer := csv.NewWriter(f)
	writer.Write([]string{"Domain", "DNSSECExists", "DNSSECValid", "reason"})
	for _, r := range results {
		row := []string{r.Domain, strconv.FormatBool(r.DNSSECExists), strconv.FormatBool(r.DNSSECValid), r.reason}
		writer.Write(row)
	}
	writer.Flush()
	f.Close()
	fmt.Printf("Successfully wrote output to %v", filePath)
}
