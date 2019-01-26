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
	var uninstall, help, verbose bool
	var java, firefox, noSystem, all bool
	flag.Usage = usage
	flag.BoolVar(&uninstall, "uninstall", false, "uninstall the given certificate")
	flag.BoolVar(&java, "java", false, "install or uninstall on the Java truststore")
	flag.BoolVar(&firefox, "firefox", false, "install or uninstall on the Firefox truststore")
	flag.BoolVar(&noSystem, "no-system", false, "disables the install or uninstall on the system truststore")
	flag.BoolVar(&all, "all", false, "install or uninstall on the system, Firefox and Java truststores")
	flag.BoolVar(&verbose, "v", false, "be verbose")
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

	var opts []truststore.Option
	if all {
		opts = append(opts, truststore.WithJava(), truststore.WithFirefox())
	} else {
		if java {
			opts = append(opts, truststore.WithJava())
		}
		if firefox {
			opts = append(opts, truststore.WithFirefox())
		}
	}
	if noSystem {
		opts = append(opts, truststore.WithNoSystem())
	}
	if verbose {
		opts = append(opts, truststore.WithDebug())
	}

	if uninstall {
		if err := truststore.UninstallFile(flag.Arg(0), opts...); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	} else {
		if err := truststore.InstallFile(flag.Arg(0), opts...); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
}
