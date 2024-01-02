/*
   Certificate Validation Server (CVS) is a server for CA about returning certificate status via OCSP and CRL.
   Copyright (C) 2024  Levi Marvin (LIU, YUANCHEN)

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
	"fmt"
)

func DecodeCertificatePEM(raw []byte) (*x509.Certificate, error) {
	pemCert, _ := pem.Decode(raw)
	if len(pemCert.Bytes) == 0 {
		return nil, errors.New(fmt.Sprintf("unable to decode the PEM-encoded certificate: <%v>", raw))
	}
	cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

func DecodeRSAWithPKCS1PrivateKeyPEM(raw []byte) (crypto.Signer, error) {
	// Decode PEM data and check the decoding failure
	pemKey, _ := pem.Decode(raw)
	if len(pemKey.Bytes) == 0 {
		// return error if decoding failure
		return nil, errors.New(fmt.Sprintf("unable to decode the PEM-encoded private key: <%v>", raw))
	}
	key, err := x509.ParsePKCS1PrivateKey(pemKey.Bytes)
	if err != nil {
		return nil, err
	}
	return key, err
}

func DecodeRSAWithPKCS8PrivateKeyPEM(raw []byte) (any, error) {
	// Decode PEM data and check the decoding failure
	pemKey, _ := pem.Decode(raw)
	if len(pemKey.Bytes) == 0 {
		// return error if decoding failure
		return nil, errors.New(fmt.Sprintf("unable to decode the PEM-encoded private key: <%v>", raw))
	}
	key, err := x509.ParsePKCS8PrivateKey(pemKey.Bytes)
	if err != nil {
		return nil, err
	}
	return key, err
}

func DecodeECPrivateKeyPEM(raw []byte) (crypto.Signer, error) {
	// Decode PEM data and check the decoding failure
	pemKey, _ := pem.Decode(raw)
	if len(pemKey.Bytes) == 0 {
		// return error if decoding failure
		return nil, errors.New(fmt.Sprintf("unable to decode the PEM-encoded private key: <%v>", raw))
	}
	key, err := x509.ParseECPrivateKey(pemKey.Bytes)
	if err != nil {
		return nil, err
	}
	return key, err
}
