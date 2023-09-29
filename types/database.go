package types

import (
	"gorm.io/gorm"
	"time"
)

type DbResponder struct {
	gorm.Model
	Name               string `gorm:"column:responder_name"`
	UpdatePeriod       string `gorm:"column:update_period"`
	CACertificate      []byte `gorm:"column:ca_cert_blob"`
	SigningCertificate []byte `gorm:"column:signer_cert_blob"`
	SigningKey         []byte `gorm:"column:signer_key_blob"`
	SigningKeyType     string `gorm:"column:signer_key_type"`
	EnableNonce        bool   `gorm:"column:nonce"`
	EnableCutOff       bool   `gorm:"column:cutoff"`
}

func (DbResponder) TableName() string {
	return "responder_list"
}

type CertificateInfo struct {
	gorm.Model
	// Version is the version of certificate. Only has "V1" (0), "V2" (1), "V3" (2),
	// it can be got from the field cert.Version
	Version   int
	Algorithm string
	// RawIssuerName
	// it can be got from the function cert.RawIssuerName
	RawIssuerName []byte
	// RawSubjectName
	// it can be got from the function cert.RawSubjectName
	RawSubjectName  []byte
	SerialNumber    []byte
	HashAlgorithm   string
	IssuerNameHash  string
	SubjectKeyHash  string
	SubjectNameHash string
	NotAfter        time.Time
	NotBefore       time.Time
	IsCA            bool

	IsRevoked        bool
	RevocationTime   time.Time
	RevocationReason int
}

func (certInfo CertificateInfo) IsEmpty() bool {
	return certInfo.Version == CertificateInfo{}.Version
}

func (CertificateInfo) TableName() string {
	return "certificate_list"
}
