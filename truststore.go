// Copyright (c) 2018 The truststore Authors. All rights reserved.

package truststore

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
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

var prefix = "Truststore Development CA "
var enableDebug bool

func debug(format string, args ...interface{}) {
	if enableDebug {
		log.Printf(format, args...)
	}
}

// Install installs the given certificate into the system truststore, and
// optionally to the Firefox and Java trustores.
func Install(cert *x509.Certificate, opts ...Option) error {
	filename, fn, err := saveTempCert(cert)
	defer fn()
	if err != nil {
		return err
	}
	return installCertificate(filename, cert, opts)
}

// InstallFile will read the certificate in the given file and install it to the
// system truststore, and optionally to the Firefox and Java truststores.
func InstallFile(filename string, opts ...Option) error {
	cert, err := ReadCertificate(filename)
	if err != nil {
		return err
	}
	return installCertificate(filename, cert, opts)
}

func installCertificate(filename string, cert *x509.Certificate, opts []Option) error {
	o := newOptions(opts)
	if o.withJava {

	}
	if o.withFirefox && hasNSS() {
		if !checkNSS(cert) {
			if err := installNSS(filename, cert); err != nil {
				return err
			}
		}
	}
	if o.withNoSystem {
		return nil
	}

	return installPlatform(filename, cert)
}

// Uninstall removes the given certificate from the system truststore, and
// optionally from the Firefox and Java truststres.
func Uninstall(cert *x509.Certificate, opts ...Option) error {
	filename, fn, err := saveTempCert(cert)
	defer fn()
	if err != nil {
		return err
	}
	return uninstallCertificate(filename, cert, opts)
}

// UninstallFile reads the certificate in the given file and removes it from the
// system truststore, and optionally to the Firefox and Java truststores.
func UninstallFile(filename string, opts ...Option) error {
	cert, err := ReadCertificate(filename)
	if err != nil {
		return err
	}
	return uninstallCertificate(filename, cert, opts)
}

func uninstallCertificate(filename string, cert *x509.Certificate, opts []Option) error {
	o := newOptions(opts)
	if o.withJava {

	}
	if o.withFirefox && checkNSS(cert) {
		if err := uninstallNSS(filename, cert); err != nil {
			return err
		}
	}
	if o.withNoSystem {
		return nil
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

// SaveCertificate saves the given x509.Certificate with the given filename.
func SaveCertificate(filename string, cert *x509.Certificate) error {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return ioutil.WriteFile(filename, pem.EncodeToMemory(block), 0600)
}

type options struct {
	withJava     bool
	withFirefox  bool
	withNoSystem bool
}

func newOptions(opts []Option) *options {
	o := new(options)
	for _, fn := range opts {
		fn(o)
	}
	return o
}

// Option is the type used to pass custom options.
type Option func(*options)

// WithJava enables the install or uninstall of a certificate in the Java
// truststore.
func WithJava() Option {
	return func(o *options) {
		o.withJava = true
	}
}

// WithFirefox enables the install or uninstall of a certificate in the Firefox
// truststore.
func WithFirefox() Option {
	return func(o *options) {
		o.withFirefox = true
	}
}

// WithNoSystem disables the install or uninstall of a certificate in the system
// truststore.
func WithNoSystem() Option {
	return func(o *options) {
		o.withNoSystem = true
	}
}

// WithDebug enables debug logging messages.
func WithDebug() Option {
	return func(o *options) {
		enableDebug = true
	}
}

// WithPrefix sets a custom prefix for the truststore name.
func WithPrefix(s string) Option {
	return func(o *options) {
		prefix = s
	}
}

func uniqueName(cert *x509.Certificate) string {
	return prefix + cert.SerialNumber.String()
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

func saveTempCert(cert *x509.Certificate) (string, func(), error) {
	f, err := ioutil.TempFile(os.TempDir(), "truststore.*.pem")
	if err != nil {
		return "", func() {}, err
	}
	name := f.Name()
	clean := func() {
		os.Remove(name)
	}
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return name, clean, err
}
