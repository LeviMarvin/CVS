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

package util

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"strings"
)

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

func DecodePEMCertificateFile(reader io.Reader) (*x509.Certificate, error) {
	cacertFileBlobs, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	cacertData, _ := pem.Decode(cacertFileBlobs)
	if err != nil {
		return nil, err
	}
	cacert, err := x509.ParseCertificate(cacertData.Bytes)
	if err != nil {
		return nil, err
	}
	return cacert, nil
}
