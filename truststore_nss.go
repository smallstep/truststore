// Copyright (c) 2018 The truststore Authors. All rights reserved.
// Copyright (c) 2018 The mkcert Authors. All rights reserved.

package truststore

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	certutilPath string
	nssDB        = filepath.Join(os.Getenv("HOME"), ".pki/nssdb")
)

func hasNSS() bool {
	for _, path := range []string{
		"/usr/bin/firefox", nssDB, "/Applications/Firefox.app",
		"/Applications/Firefox Developer Edition.app",
		"/Applications/Firefox Nightly.app",
		"C:\\Program Files\\Mozilla Firefox",
	} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	// Try with user defined path
	if path := os.Getenv("TRUSTSTORE_NSS_LOCATION"); path != "" {
		if _, err := os.Stat(path); err == nil {
			fmt.Println()
			return true
		} else {
			println(err.Error())
		}
	}

	debug("%s not found. Try to define the environment variable TRUSTSTORE_NSS_LOCATION", NSSBrowsers)
	return false
}

func hasCertUtil() bool {
	var err error
	switch runtime.GOOS {
	case "darwin":
		certutilPath, err = exec.LookPath("certutil")
		if err != nil {
			out, err1 := exec.Command("brew", "--prefix", "nss").Output()
			if err1 != nil {
				return false
			}
			certutilPath = filepath.Join(strings.TrimSpace(string(out)), "bin", "certutil")
			_, err = os.Stat(certutilPath)
		}
		return err == nil
	case "linux":
		certutilPath, err = exec.LookPath("certutil")
		return err == nil
	default:
		return false
	}
}

func checkNSS(cert *x509.Certificate) bool {
	if !hasCertUtil() {
		if CertutilInstallHelp == "" {
			debug("Note: %s support is not available on your platform. ℹ️", NSSBrowsers)
		} else {
			debug(`Warning: "certutil" is not available, so the certificate can't be automatically installed in %s!`, NSSBrowsers)
			debug(`Install "certutil" with "%s" and try again`, CertutilInstallHelp)
		}
		return false
	}

	// Check if the certificate is already installed
	success := true
	if forEachNSSProfile(func(profile string) {
		err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", uniqueName(cert)).Run()
		if err != nil {
			success = false
		}
	}) == 0 {
		success = false
	}
	return success
}

func installNSS(filename string, cert *x509.Certificate) error {
	// install certificate in all profiles
	if forEachNSSProfile(func(profile string) {
		cmd := exec.Command(certutilPath, "-A", "-d", profile, "-t", "C,,", "-n", uniqueName(cert), "-i", filename)
		out, err := cmd.CombinedOutput()
		if err != nil {
			debug("failed to execute \"certutil -A\": %s\n\n%s", err, out)
		}
	}) == 0 {
		return fmt.Errorf("not %s security databases found", NSSBrowsers)
	}
	// check for the cert in all profiles
	if !checkNSS(cert) {
		return fmt.Errorf("certificate cannot be installed in %s", NSSBrowsers)
	}
	debug("certificate installed properly in %s", NSSBrowsers)
	return nil
}

func uninstallNSS(filname string, cert *x509.Certificate) (err error) {
	forEachNSSProfile(func(profile string) {
		if err != nil {
			return
		}
		// skip if not found
		if err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", uniqueName(cert)).Run(); err != nil {
			return
		}
		// delete certificate
		cmd := exec.Command(certutilPath, "-D", "-d", profile, "-n", uniqueName(cert))
		out, err1 := cmd.CombinedOutput()
		if err1 != nil {
			err = cmdError(err1, "certutil -D", out)
		}
	})
	return
}

func forEachNSSProfile(f func(profile string)) (found int) {
	profiles, _ := filepath.Glob(FirefoxProfile)
	if _, err := os.Stat(nssDB); err == nil {
		profiles = append(profiles, nssDB)
	}
	if len(profiles) == 0 {
		return
	}
	for _, profile := range profiles {
		if stat, err := os.Stat(profile); err != nil || !stat.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(profile, "cert9.db")); err == nil {
			f("sql:" + profile)
			found++
			continue
		}
		if _, err := os.Stat(filepath.Join(profile, "cert8.db")); err == nil {
			f("dbm:" + profile)
			found++
		}
	}
	return
}
