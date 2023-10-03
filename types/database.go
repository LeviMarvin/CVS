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
