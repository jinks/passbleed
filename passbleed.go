package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Different CSV formats
const (
	UnknownFormat = -1 + iota
	LastPassFormat
	_
	_
	KeePass1Format
	KeePassXFormat
	_
	_
	_
	OnePasswordFormat
)

// Domain to check
// +gen set
type Domain string

func findCSVType(reader *csv.Reader) (int, error) {
	header, err := reader.Read()
	if err == io.EOF {
		return UnknownFormat, fmt.Errorf("empty CSV file")
	} else if err != nil {
		return UnknownFormat, err
	}
	switch {
	case len(header) >= 1 && header[0] == "url":
		return LastPassFormat, nil
	case len(header) >= 4 && header[3] == "Web Site":
		return KeePass1Format, nil
	case len(header) >= 5 && header[4] == "URL":
		return KeePassXFormat, nil
	case len(header) >= 9 && header[8] == "urls":
		return OnePasswordFormat, nil
	default:
		return UnknownFormat, fmt.Errorf("unkonwn CSV format, please use a supported export format (see README)")
	}
}

func buildKeepass(filename string) (*DomainSet, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.LazyQuotes = true
	col, err := findCSVType(reader)
	if err != nil {
		return nil, err
	}

	kpDomains := NewDomainSet()
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		// If we get a bare hostname without scheme, url.Parse sets the host
		// as empty and puts the full hostname in Path. Add a "http://" in
		// front of bare hosts to prevent that.
		if !strings.Contains(record[col], "//") {
			record[col] = "http://" + record[col]
		}
		potential, err := url.Parse(record[col])
		if err != nil {
			continue
		}
		tld, err := publicsuffix.EffectiveTLDPlusOne(potential.Hostname())
		if err != nil {
			continue
		}
		kpDomains.Add(Domain(tld))
	}
	return &kpDomains, nil
}

func buildCloudBleed(filename string) (*DomainSet, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	cbDomains := NewDomainSet()
	for scanner.Scan() {
		cbDomains.Add(Domain(scanner.Text()))
	}
	return &cbDomains, scanner.Err()
}

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(2)
	}
	fmt.Print("Building KeePass domain list... ")
	keepass, err := buildKeepass(os.Args[1])
	if err != nil {
		fmt.Println("Error building KeePass domain list:", err)
		os.Exit(1)
	}
	fmt.Println(keepass.Cardinality(), "domains found.")

	fmt.Print("Building CloudBleed domain list... ")
	cloudBleed, err := buildCloudBleed(os.Args[2])
	if err != nil {
		fmt.Println("Error building CloudBleed domain list:", err)
		os.Exit(1)
	}
	fmt.Print(cloudBleed.Cardinality(), " domains found.\n\n")

	inDanger := keepass.Intersect(*cloudBleed).ToSlice()
	sort.Slice(inDanger, func(i, j int) bool { return inDanger[i] < inDanger[j] })
	fmt.Println(len(inDanger), "potentially endangered domains:")
	for _, k := range inDanger {
		fmt.Println(k)
	}

}

func usage() {
	fmt.Println(`usage: ` + os.Args[0] + ` <keepass.csv> <sorted_unique_cf.txt>`)
}
