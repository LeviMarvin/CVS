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

func HttpIndexHandler(w http.ResponseWriter, r *http.Request) {
	// Load responders from database
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
