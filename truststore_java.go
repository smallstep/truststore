// Copyright (c) 2018 The truststore Authors. All rights reserved.
// Copyright (c) 2018 The mkcert Authors. All rights reserved.

package truststore

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	hasJava    bool
	hasKeytool bool

	javaHome    string
	cacertsPath string
	keytoolPath string
	storePass   string = "changeit"
)

func init() {
	if runtime.GOOS == "windows" {
		keytoolPath = filepath.Join("bin", "keytool.exe")
	} else {
		keytoolPath = filepath.Join("bin", "keytool")
	}

	if v := os.Getenv("JAVA_HOME"); v != "" {
		hasJava = true
		javaHome = v

		_, err := os.Stat(filepath.Join(v, keytoolPath))
		if err == nil {
			hasKeytool = true
			keytoolPath = filepath.Join(v, keytoolPath)
		}

		_, err = os.Stat(filepath.Join(v, "lib", "security", "cacerts"))
		if err == nil {
			cacertsPath = filepath.Join(v, "lib", "security", "cacerts")
		}

		_, err = os.Stat(filepath.Join(v, "jre", "lib", "security", "cacerts"))
		if err == nil {
			cacertsPath = filepath.Join(v, "jre", "lib", "security", "cacerts")
		}

		println(cacertsPath)
	}
}

func checkJava(cert *x509.Certificate) bool {
	if !hasKeytool {
		return false
	}

	// exists returns true if the given x509.Certificate's fingerprint
	// is in the keytool -list output
	exists := func(c *x509.Certificate, h hash.Hash, keytoolOutput []byte) bool {
		h.Write(c.Raw)
		fp := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
		return bytes.Contains(keytoolOutput, []byte(fp))
	}

	keytoolOutput, err := exec.Command(keytoolPath, "-list", "-keystore", cacertsPath, "-storepass", storePass).CombinedOutput()
	if err != nil {
		debug("failed to execute \"keytool -list\": %s\n\n%s", err, keytoolOutput)
		return false
	}

	// keytool outputs SHA1 and SHA256 (Java 9+) certificates in uppercase hex
	// with each octet pair delimitated by ":". Drop them from the keytool output
	keytoolOutput = bytes.Replace(keytoolOutput, []byte(":"), nil, -1)

	// pre-Java 9 uses SHA1 fingerprints
	s1, s256 := sha1.New(), sha256.New()
	return exists(cert, s1, keytoolOutput) || exists(cert, s256, keytoolOutput)
}

func installJava(filename string, cert *x509.Certificate) error {
	args := []string{
		"-importcert", "-noprompt",
		"-keystore", cacertsPath,
		"-storepass", storePass,
		"-file", filename,
		"-alias", uniqueName(cert),
	}

	out, err := execKeytool(exec.Command(keytoolPath, args...))
	if err != nil {
		return cmdError(err, "keytool -importcert", out)
	}

	return nil
}

func uninstallJava(filename string, cert *x509.Certificate) error {
	args := []string{
		"-delete",
		"-alias", uniqueName(cert),
		"-keystore", cacertsPath,
		"-storepass", storePass,
	}
	out, err := execKeytool(exec.Command(keytoolPath, args...))
	if bytes.Contains(out, []byte("does not exist")) {
		return nil
	}
	if err != nil {
		cmdError(err, "keytool -delete", out)
	}
	return nil
}

// execKeytool will execute a "keytool" command and if needed re-execute
// the command wrapped in 'sudo' to work around file permissions.
func execKeytool(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if err != nil && bytes.Contains(out, []byte("java.io.FileNotFoundException")) && runtime.GOOS != "windows" {
		origArgs := cmd.Args[1:]
		cmd = exec.Command("sudo", keytoolPath)
		cmd.Args = append(cmd.Args, origArgs...)
		cmd.Env = []string{
			"JAVA_HOME=" + javaHome,
		}
		out, err = cmd.CombinedOutput()
	}
	return out, err
}
