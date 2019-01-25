package truststore

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

var (
	// ErrNotSupported is the error to indicate that the install of the
	// certificate is not supported on the system.
	ErrNotSupported = errors.New("install is not supported on this system")

	// ErrNotFound is the error to indicate that a cert was not found.
	ErrNotFound = errors.New("no certs found")

	// ErrInvalidCertificate is the error to indicate that a cert contains bad data.
	ErrInvalidCertificate = errors.New("invalid PEM data")
)

// InstallCertificate the given certificate to the system truststore.
func InstallCertificate(filename string) error {
	cert, err := ReadCertificate(filename)
	if err != nil {
		return err
	}
	return installPlatform(filename, cert)
}

// UninstallCertificate removes the given file from the system truststore.
func UninstallCertificate(filename string) error {
	cert, err := ReadCertificate(filename)
	if err != nil {
		return err
	}
	return uninstallPlatform(filename, cert)
}

// ReadCertificate reads a certificate file and returns a x509.Certificate struct.
func ReadCertificate(filename string) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// PEM format
	if bytes.HasPrefix(b, []byte("-----BEGIN ")) {
		b, err = ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		block, _ := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, ErrInvalidCertificate
		}
		b = block.Bytes
	}

	// DER format (binary)
	crt, err := x509.ParseCertificate(b)
	return crt, wrapError(err, "error parsing "+filename)
}

func uniqueName(cert *x509.Certificate) string {
	return "truststore development CA " + cert.SerialNumber.String()
}

func cmdError(err error, command string, out []byte) error {
	return fmt.Errorf("failed to execute \"%s\": %s\n\n%s", command, err, out)
}

func wrapError(err error, msg string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %s", msg, err)
}
