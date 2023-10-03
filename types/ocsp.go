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
