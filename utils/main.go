// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/html/charset"
)

func main() {
	dec := xml.NewDecoder(os.Stdin)
	dec.CharsetReader = charset.NewReaderLabel
	dec.Strict = false

	var doc Registry
	if err := dec.Decode(&doc); err != nil {
		log.Fatal(err)
	}

	M := make(map[string]int)

	for _, r := range doc.Registry {
		if r.ID == "content-formats" {
			for _, x := range r.Record {
				mt := x.Contenttype
				if strings.HasPrefix(mt, "Unassigned") ||
					strings.HasPrefix(mt, "Reserved") ||
					strings.Contains(mt, "TEMPORARY") {
					continue
				}
				id, err := strconv.Atoi(x.ID)
				if err != nil {
					log.Fatal(err)
				}

				M[mt] = id
			}
		}
	}

	fmt.Println("// auto-generated (see utils/README.md)")
	fmt.Println("package cmw")
	fmt.Println("")
	fmt.Println("var mt2cf = map[string]uint16{")
	for k, v := range M {
		fmt.Printf("\t`%s`: %d,\n", k, v)
	}
	fmt.Println("}")
	fmt.Println("")
	fmt.Println("var cf2mt = map[uint16]string{")
	for k, v := range M {
		fmt.Printf("\t%d: `%s`,\n", v, k)
	}
	fmt.Println("}")
}
