// Copyright (c) 2018 The truststore Authors. All rights reserved.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/smallstep/truststore"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n\t%s [-uninstall] rootCA.pem\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var uninstall, help bool
	flag.Usage = usage
	flag.BoolVar(&uninstall, "uninstall", false, "uninstall the given certificate")
	flag.BoolVar(&help, "help", false, "show help")
	flag.Parse()

	if help {
		flag.Usage()
		os.Exit(0)
	}

	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(1)
	}

	if uninstall {
		if err := truststore.UninstallCertificate(flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	} else {
		if err := truststore.InstallCertificate(flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
}
