// Copyright (c) 2018 The truststore Authors. All rights reserved.
// Copyright (c) 2018 The mkcert Authors. All rights reserved.

package truststore

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

var (
	// NSSProfile is the path of the Firefox profiles.
	NSSProfile = os.Getenv("HOME") + "/.mozilla/firefox/*"

	// CertutilInstallHelp is the command to run on linux to add NSS support.
	CertutilInstallHelp = `apt install libnss3-tools" or "yum install nss-tools`

	// SystemTrustFilename is the format used to name the root certificates.
	SystemTrustFilename string

	// SystemTrustCommand is the command used to update the system truststore.
	SystemTrustCommand []string

	// whether or not the needed packages should be attempted to be installed
	TryInstallCaCommand bool

	// if the above is true, if we should also ignore the certs the repo is using
	IgnoreSslForInstall bool
)

func init() {
	setCommandAndFileVariables()

	if os.Getenv("TRUSTSTORE_INSTALL_CA_PACKAGE") == "true" {
		TryInstallCaCommand = true
	} else {
		TryInstallCaCommand = false
	}

	if os.Getenv("TRUSTSTORE_IGNORE_PACKAGE_CERTS") == "true" {
		IgnoreSslForInstall = true
	} else {
		IgnoreSslForInstall = false
	}
}

func setCommandAndFileVariables() {
	switch {
	case pathExists("/etc/pki/ca-trust/source/anchors/"):
		SystemTrustFilename = "/etc/pki/ca-trust/source/anchors/%s.pem"
		SystemTrustCommand = []string{"update-ca-trust", "extract"}
	case pathExists("/usr/local/share/ca-certificates/"):
		SystemTrustFilename = "/usr/local/share/ca-certificates/%s.crt"
		SystemTrustCommand = []string{"update-ca-certificates"}
	case pathExists("/usr/share/pki/trust/anchors/"):
		SystemTrustFilename = "/usr/share/pki/trust/anchors/%s.crt"
		SystemTrustCommand = []string{"update-ca-certificates"}
	case pathExists("/etc/ca-certificates/trust-source/anchors/"):
		SystemTrustFilename = "/etc/ca-certificates/trust-source/anchors/%s.crt"
		SystemTrustCommand = []string{"trust", "extract-compat"}
	case pathExists("/etc/ssl/certs/"):
		SystemTrustFilename = "/etc/ssl/certs/%s.crt"
		SystemTrustCommand = []string{"trust", "extract-compat"}
	}
	if SystemTrustCommand != nil {
		if !existsOnPath(SystemTrustCommand[0]) {
			SystemTrustCommand = nil
		}
	}
}

func existsOnPath(binary string) bool {
	_, err := exec.LookPath(binary)
	return err == nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func systemTrustFilename(cert *x509.Certificate) string {
	return fmt.Sprintf(SystemTrustFilename, strings.ReplaceAll(uniqueName(cert), " ", "_"))
}

func tryDetermineOsAndInstall() error {
	if !TryInstallCaCommand {
		return ErrNotSupported
	}

	debug("trying to determine OS package manager")

	// RHEL is purposefully being ignored here - even their minimal container images include the required utils.

	if existsOnPath("apk") {
		debug("using apk/alpine")
		cmd := CommandWithSudo(strings.Split("apk --no-cache add ca-certificates", " ")...)
		if IgnoreSslForInstall {
			debug("ignoring SSL for package install")
			// we need to get the alpine version because apk doesn't have a way to just ignore SSL
			// instead we need to force it to use the same repo but with HTTP
			f, err := os.Open("/etc/alpine-release")
			if err != nil {
				return ErrNotSupported
			}
			buf := make([]byte, 4)
			_, err = io.ReadAtLeast(f, buf, 4)
			if err != nil {
				return ErrNotSupported
			}
			cmd = CommandWithSudo(strings.Split(fmt.Sprintf("apk --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/v%v/main add ca-certificates", string(buf[:4])), " ")...)
		}
		err := cmd.Run()
		if err != nil {
			return ErrNotSupported
		}
		setCommandAndFileVariables()
		return nil
	}

	if existsOnPath("apt-get") {
		debug("using apt-get/debian")
		cmd := CommandWithSudo(strings.Split("apt-get update", " ")...)
		if IgnoreSslForInstall {
			debug("ignoring SSL for apt-get update")
			cmd = CommandWithSudo(strings.Split("apt-get -o \"Acquire::https::Verify-Peer=false\" update", " ")...)
		}
		err := cmd.Run()
		if err != nil {
			return ErrNotSupported
		}
		cmd = CommandWithSudo(strings.Split("apt-get install -y ca-certificates", " ")...)
		if IgnoreSslForInstall {
			debug("ignoring SSL for package install")
			cmd = CommandWithSudo(strings.Split("apt-get -o \"Acquire::https::Verify-Peer=false\" install -y ca-certificates", " ")...)
		}
		err = cmd.Run()
		if err != nil {
			return ErrNotSupported
		}
		setCommandAndFileVariables()
		return nil
	}

	return ErrNotSupported
}

func installPlatform(filename string, cert *x509.Certificate) error {
	if SystemTrustCommand == nil {
		err := tryDetermineOsAndInstall()
		if err != nil {
			return err
		}
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	cmd := CommandWithSudo("tee", systemTrustFilename(cert))
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return NewCmdError(err, cmd, out)
	}

	cmd = CommandWithSudo(SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return NewCmdError(err, cmd, out)
	}

	debug("certificate installed properly in linux trusts")
	return nil
}

func uninstallPlatform(filename string, cert *x509.Certificate) error {
	if SystemTrustCommand == nil {
		err := tryDetermineOsAndInstall()
		if err != nil {
			return err
		}
	}

	cmd := CommandWithSudo("rm", "-f", systemTrustFilename(cert))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return NewCmdError(err, cmd, out)
	}

	cmd = CommandWithSudo(SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return NewCmdError(err, cmd, out)
	}

	debug("certificate uninstalled properly from linux trusts")
	return nil
}

func CommandWithSudo(cmd ...string) *exec.Cmd {
	if _, err := exec.LookPath("sudo"); err != nil {
		//nolint:gosec // tolerable risk necessary for function
		return exec.Command(cmd[0], cmd[1:]...)
	}
	//nolint:gosec // tolerable risk necessary for function
	return exec.Command("sudo", append([]string{"--"}, cmd...)...)
}
