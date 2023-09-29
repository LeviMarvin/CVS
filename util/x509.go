package util

import (
	"CVS/types"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"gorm.io/gorm"
	"strings"
)

func ConvertToCertificateInfo(cert *x509.Certificate) (types.CertificateInfo, error) {
	if cert == nil {
		return types.CertificateInfo{}, errors.New("invalid input")
	}

	certInfo := types.CertificateInfo{
		Model:           gorm.Model{},
		Version:         cert.Version,
		Algorithm:       cert.PublicKeyAlgorithm.String(),
		RawIssuerName:   cert.RawIssuer,
		RawSubjectName:  cert.RawSubject,
		SerialNumber:    cert.SerialNumber.Bytes(),
		HashAlgorithm:   cert.PublicKeyAlgorithm.String(),
		IssuerNameHash:  HashToHex(cert.RawIssuer, sha1.New()),
		SubjectKeyHash:  HashToHex(cert.RawSubjectPublicKeyInfo, sha1.New()),
		SubjectNameHash: HashToHex(cert.RawSubject, sha1.New()),
		NotAfter:        cert.NotAfter,
		NotBefore:       cert.NotBefore,
		IsCA:            cert.IsCA,

		IsRevoked: false,
	}

	return certInfo, nil

}

// ParsePrivateKey converts input raw key blobs to crypto.Signer.
func ParsePrivateKey(raw []byte, keyType string) (crypto.Signer, error) {
	if strings.ToUpper(keyType) == "RSA" {
		key, err := x509.ParsePKCS1PrivateKey(raw)
		CheckError(err)
		return key, nil
	} else if strings.ToUpper(keyType) == "EC" {
		key, err := x509.ParseECPrivateKey(raw)
		CheckError(err)
		return key, nil
	} else {
		return nil, errors.New("failed to parse private key")
	}
}
