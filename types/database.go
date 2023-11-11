/*
   Certificate Validation Server (CVS) is a server for CA about returning certificate status via OCSP and CRL.
   Copyright (C) 2023  Levi Marvin (LIU, YUANCHEN)

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package types

import (
	"CVS/util"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"gorm.io/gorm"
	"math/big"
	"time"
)

type DbResponder struct {
	gorm.Model
	Name               string `gorm:"column:responder_name"`
	UpdatePeriod       string `gorm:"column:update_period"`
	CAId               uint   `gorm:"column:ca_id"`
	SigningCertificate []byte `gorm:"column:signer_cert_blob"`
	SigningKey         []byte `gorm:"column:signer_key_blob"`
	SigningKeyType     string `gorm:"column:signer_key_type"`
	EnableNonce        bool   `gorm:"column:nonce"`
	EnableCutOff       bool   `gorm:"column:cutoff"`
	EnableCrlEntry     bool   `gorm:"column:crlentry"`
}

func (DbResponder) TableName() string {
	return "responder_list"
}

func (r DbResponder) IsEmpty() bool {
	return r.Name == DbResponder{}.Name
}

type DbCrlDistributor struct {
	gorm.Model
	Name         string `gorm:"column:distributor_name"`
	URIPath      string `gorm:"column:access_uri"`
	UpdatePeriod string `gorm:"column:update_period"`
	CAId         uint   `gorm:"column:ca_id"`
	Number       int64  `gorm:"column:number"`
	RawCRL       []byte `gorm:"column:raw_crl"`
}

func (DbCrlDistributor) TableName() string {
	return "distributor_list"
}

func (r DbCrlDistributor) IsEmpty() bool {
	return r.Name == DbCrlDistributor{}.Name
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
	// RawSubject
	// it can be got from the function cert.RawSubject
	RawSubject      []byte
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

	CAId uint
}

func (certInfo CertificateInfo) IsEmpty() bool {
	return certInfo.Version == CertificateInfo{}.Version
}

func (CertificateInfo) TableName() string {
	return "certificate_list"
}

func (certInfo CertificateInfo) ToRevocationListEntry() *x509.RevocationListEntry {
	sn := new(big.Int)
	sn.SetBytes(certInfo.SerialNumber)
	entry := x509.RevocationListEntry{
		SerialNumber:   sn,
		RevocationTime: certInfo.RevocationTime,
		ReasonCode:     certInfo.RevocationReason,
	}
	return &entry
}

func ConvertToBasicCertificateInfo(cert *x509.Certificate) (CertificateInfo, error) {
	if cert == nil {
		return CertificateInfo{}, errors.New("invalid input")
	}

	certInfo := CertificateInfo{
		Model:           gorm.Model{},
		Version:         cert.Version,
		Algorithm:       cert.PublicKeyAlgorithm.String(),
		RawIssuerName:   cert.RawIssuer,
		RawSubject:      cert.RawSubject,
		SerialNumber:    cert.SerialNumber.Bytes(),
		HashAlgorithm:   cert.PublicKeyAlgorithm.String(),
		IssuerNameHash:  util.HashToHex(cert.RawIssuer, sha1.New()),
		SubjectKeyHash:  util.HashToHex(cert.RawSubjectPublicKeyInfo, sha1.New()),
		SubjectNameHash: util.HashToHex(cert.RawSubject, sha1.New()),
		NotAfter:        cert.NotAfter,
		NotBefore:       cert.NotBefore,
		IsCA:            cert.IsCA,

		IsRevoked: false,
	}

	return certInfo, nil

}

func FetchCertIssuerID(cert *x509.Certificate, db *gorm.DB) (uint, error) {
	if cert == nil || db == nil {
		return 0, errors.New("invalid input")
	}

	caInfo := CertificateAuthorityInfo{}
	db.Find(&caInfo, &CertificateAuthorityInfo{RawSubject: cert.RawIssuer})
	if caInfo.IsEmpty() {
		return 0, nil
	}

	return caInfo.ID, nil
}

type CertificateAuthorityInfo struct {
	gorm.Model

	CommonName     string
	SubjectKeyHash string

	RawSubject []byte
	// RawIssuerName
	// it can be got from the function cert.RawIssuerName
	RawIssuerName []byte
	// RawSubjectName
	// it can be got from the function cert.RawSubject
	RawSubjectName  []byte
	CertificateBlob []byte
	KeyBlob         []byte
	KeyType         string
}

func (caInfo CertificateAuthorityInfo) IsEmpty() bool {
	return caInfo.CommonName == CertificateAuthorityInfo{}.CommonName
}

func (CertificateAuthorityInfo) TableName() string {
	return "ca_list"
}

func (caInfo CertificateAuthorityInfo) ToCA() (*CertificateAuthority, error) {
	// Create CertificateAuthority struct
	cert, err := x509.ParseCertificate(caInfo.CertificateBlob)
	if err != nil {
		return nil, err
	}
	key, err := util.ParsePrivateKey(caInfo.KeyBlob, caInfo.KeyType)
	if err != nil {
		return nil, err
	}
	ca := CertificateAuthority{
		ID:             caInfo.ID,
		Name:           caInfo.CommonName,
		CACert:         cert,
		SubjectKeyHash: util.HashToHex(cert.RawSubjectPublicKeyInfo, sha1.New()),
		CAKey:          key,
		CAKeyType:      caInfo.KeyType,
	}

	return &ca, nil
}
