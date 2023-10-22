package types

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"gorm.io/gorm"
	"math/big"
	"time"
)

type CertificateAuthority struct {
	ID             uint
	Name           string
	CACert         *x509.Certificate
	SubjectKeyHash string
	CAKey          crypto.Signer
	CAKeyType      string
}

func (ca CertificateAuthority) FetchRevokedEntries(db *gorm.DB) *[]x509.RevocationListEntry {
	// Get revoked certificates of the CA
	condition := CertificateInfo{
		CAId:      ca.ID,
		IsRevoked: true,
	}
	var revokedCerts []CertificateInfo
	db.Where(&condition).Find(&revokedCerts)
	var revocationEntries []x509.RevocationListEntry
	for _, cert := range revokedCerts {
		revocationEntries = append(revocationEntries, *cert.ToRevocationListEntry())
	}
	return &revocationEntries
}

func (ca CertificateAuthority) CreateBasicCRL(revokedEntries []x509.RevocationListEntry, number int64, period time.Duration, algo x509.SignatureAlgorithm) (*x509.RevocationList, error) {
	sn := new(big.Int)
	sn.SetInt64(number)
	template := x509.RevocationList{
		Issuer:                    ca.CACert.Subject,
		AuthorityKeyId:            ca.CACert.SubjectKeyId,
		SignatureAlgorithm:        algo,
		RevokedCertificateEntries: revokedEntries,
		Number:                    sn,
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(period),
		ExtraExtensions:           nil,
	}
	basicListData, err := x509.CreateRevocationList(rand.Reader, &template, ca.CACert, ca.CAKey)
	if err != nil {
		return nil, err
	}
	basicList, err := x509.ParseRevocationList(basicListData)
	if err != nil {
		return nil, err
	}
	return basicList, nil
}
