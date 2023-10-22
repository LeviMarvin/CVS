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

package responder

import (
	"CVS/shared"
	"CVS/types"
	"CVS/util"
	"crypto"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io"
	"net/http"
	"time"
)

func OcspHttpIndexHandler(w http.ResponseWriter, r *http.Request) {
	// Parse received request
	err := r.ParseForm()
	util.CheckError(err)
	// Read body data from the request
	data, err := io.ReadAll(r.Body)
	util.CheckError(err)
	if err != nil {
		w.Header().Add("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(nil)
	}
	// Create OCSP Request from body data
	ocspRequest, requestExts, err := ocsp.ParseRequestWithExtensions(data)
	util.CheckError(err)
	fmt.Printf("Received OCSP request for certificate (SN: %s) with %s algorithm\n", hex.EncodeToString(ocspRequest.SerialNumber.Bytes()), ocspRequest.HashAlgorithm.String())
	// Get matched responder
	responder, err := FetchMatchedResponder(ocspRequest)
	util.CheckError(err)
	if err != nil {
		fmt.Println("An error happened, stop to response.")
		return
	}
	// Create OCSP Response
	ocspResponse := ocsp.Response{
		Status:           ocsp.Unknown,
		SerialNumber:     ocspRequest.SerialNumber,
		ProducedAt:       time.Time{},
		ThisUpdate:       time.Time{},
		NextUpdate:       time.Time{},
		IssuerHash:       crypto.SHA256,
		RawResponderName: responder.SigningCert.RawSubject,
		//ResponderKeyHash:   responder.SigningCert.SubjectKeyId,
	}
	// Use the same hash algorithm with the request
	ocspResponse.IssuerHash = ocspRequest.HashAlgorithm
	// Add response extensions if extensions support is enabled
	ocspResponse.ResponseExtensions = make([]pkix.Extension, 0)
	if responder.FeatureTable[shared.StringNonce] {
		if util.IsExistsX509Extension(shared.OidIdPkixOcspNonce, requestExts) {
			nonceExt := pkix.Extension{
				Id:       shared.OidIdPkixOcspNonce,
				Critical: false,
				Value:    requestExts[0].Value,
			}
			ocspResponse.ResponseExtensions = append(ocspResponse.ResponseExtensions, nonceExt)
		}
	}
	// Get certificate revocation status from database
	certInfo := types.CertificateInfo{}
	shared.GetDAO().Find(&certInfo, &types.CertificateInfo{SerialNumber: ocspRequest.SerialNumber.Bytes()})
	if !certInfo.IsEmpty() {
		if !certInfo.IsRevoked {
			ocspResponse.Status = ocsp.Good
		} else {
			ocspResponse.Status = ocsp.Revoked
			// Check revocation time
			if !certInfo.RevocationTime.Equal(time.Time{}) {
				ocspResponse.RevokedAt = certInfo.RevocationTime
			} else {
				fmt.Println("Certificate is revoked but no revocation time. Use the time of now.")
				ocspResponse.RevokedAt = time.Now()
			}
			// Check revocation reason
			if certInfo.RevocationReason != 0 {
				// The default value of revocation reason in database is zero.
				ocspResponse.RevocationReason = certInfo.RevocationReason
			} else {
				ocspResponse.RevocationReason = ocsp.Unspecified
			}
		}
	} else {
		// Unable to get the certificate info from database
		ocspResponse.Status = ocsp.Unknown
	}
	// Set time in response
	ocspResponse.ThisUpdate = time.Now()
	ocspResponse.NextUpdate = time.Now().Add(responder.Period)
	// Add signer certificate
	ocspResponse.Certificate = responder.SigningCert
	// Sign the response
	ocspResponse.ProducedAt = time.Now()
	responseData, err := ocsp.CreateResponse(responder.CACert, responder.SigningCert, ocspResponse, responder.SigningSigner)
	util.CheckError(err)
	if err != nil {
		fmt.Println("An error happened, stop to response.")
		return
	}
	// Set http response
	w.Header().Add("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	// Send HTTP response
	_, err = w.Write(responseData)
	util.CheckError(err)
}

func FetchMatchedResponder(ocspRequest *ocsp.Request) (*types.Responder, error) {
	if len(shared.Responders) == 0 {
		return nil, errors.New("this error should not be happened, there are no responders in shared storage")
	}
	for _, responder := range shared.Responders {
		if ocspRequest.IssuerKeyHash != nil {
			keyHash := responder.HashTable[ocspRequest.HashAlgorithm.String()][shared.StringSubjectKeyHash]
			if keyHash == "" {
				keyHash = util.HashToHex(responder.CARawSubjectKeyId, ocspRequest.HashAlgorithm.New())
				responder.HashTable[ocspRequest.HashAlgorithm.String()][shared.StringSubjectKeyHash] = keyHash
			}
			if keyHash == hex.EncodeToString(ocspRequest.IssuerKeyHash) {
				return &responder, nil
			}
		}
		if ocspRequest.IssuerKeyHash != nil {
			nameHash := responder.HashTable[ocspRequest.HashAlgorithm.String()][shared.StringSubjectNameHash]
			if nameHash == "" {
				nameHash = util.HashToHex(responder.CARawSubject, ocspRequest.HashAlgorithm.New())
				responder.HashTable[ocspRequest.HashAlgorithm.String()][shared.StringSubjectNameHash] = nameHash
			}
			if nameHash == hex.EncodeToString(ocspRequest.IssuerNameHash) {
				return &responder, nil
			}
		}
	}
	return nil, errors.New("no matched responder found")
}
