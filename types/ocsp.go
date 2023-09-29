package types

import (
	"crypto"
	"crypto/x509"
	"time"
)

type Responder struct {
	Name              string
	CACert            *x509.Certificate
	CARawSubject      []byte
	CARawSubjectKeyId []byte
	SigningCert       *x509.Certificate
	SigningSigner     crypto.Signer
	Period            time.Duration

	// FeatureTable stored the status of features
	FeatureTable map[string]bool

	// HashTable stored hash values of responder.
	// For example: "SHA-1": {"SubjectNameHash": "0123456789abcdef"}
	HashTable map[string]map[string]string
}
