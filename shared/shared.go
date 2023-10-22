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

package shared

import (
	"CVS/types"
	"CVS/util"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"io"
	"os"
	"strconv"
	"time"
)

var ConfigRoot = types.CVS{}

var dao *gorm.DB
var Responders []types.Responder
var Distributors []types.Distributor

var OcspRspAddress = ""
var CrlDistAddress = ""

// InitSharedStorage Each independent application should call this function at first.
// This function will auto prepare shared objects.
func InitSharedStorage() {
	printLicense()
	loadXmlConfig()
	connectDatabase()
	loadResponders()
	loadDistributors()

	println()
}

func GetDAO() *gorm.DB {
	if dao != nil {
		return dao
	}
	return nil
}

func loadXmlConfig() {
	file, err := os.Open("configs/cvs.xml")
	util.PanicOnError(err)
	raw, err := io.ReadAll(file)
	util.CheckError(err)
	err = xml.Unmarshal(raw, &ConfigRoot)
	util.PanicOnError(err)
	fmt.Println("Loaded config file successfully.")
	OcspRspAddress = ConfigRoot.Functions.OCSP.Address + ":" + strconv.Itoa(ConfigRoot.Functions.OCSP.Port)
	CrlDistAddress = ConfigRoot.Functions.CRL.Address + ":" + strconv.Itoa(ConfigRoot.Functions.CRL.Port)
}

func connectDatabase() {
	var err error
	dao, err = gorm.Open(sqlite.Open(ConfigRoot.Database.FilePath), &gorm.Config{})
	util.PanicOnError(err)
	err = dao.AutoMigrate(&types.CertificateAuthorityInfo{})
	util.CheckError(err)
	err = dao.AutoMigrate(&types.CertificateInfo{})
	util.CheckError(err)
	err = dao.AutoMigrate(&types.DbCrlDistributor{})
	util.CheckError(err)
	err = dao.AutoMigrate(&types.DbResponder{})
	util.CheckError(err)
}

// loadResponders Load all of DbResponder from database and convert them to Responder.
func loadResponders() {
	var dbResponders = make([]types.DbResponder, 0)
	dao.Find(&dbResponders)

	if len(dbResponders) == 0 {
		fmt.Println("There are no responders in database, stop loading.")
		return
	}

	for _, v := range dbResponders {
		// Get CA
		caInfo := types.CertificateAuthorityInfo{}
		caInfo.ID = v.CAId
		dao.Find(&caInfo)
		ca, err := caInfo.ToCA()
		util.PanicOnError(err)
		// Load the certificate and key
		cert, err := x509.ParseCertificate(v.SigningCertificate)
		util.CheckError(err)
		signer, err := util.ParsePrivateKey(v.SigningKey, v.SigningKeyType)
		util.CheckError(err)
		// Build the FeatureTable in Responder
		featureTable := make(map[string]bool)
		if v.EnableNonce {
			featureTable[StringNonce] = true
		} else {
			featureTable[StringNonce] = false
		}
		if v.EnableCutOff {
			featureTable[StringCutoff] = true
		} else {
			featureTable[StringCutoff] = false
		}
		// Build the HashTable in Responder
		hashTable := make(map[string]map[string]string)
		hashTable[crypto.SHA1.String()] = make(map[string]string)
		hashTable[crypto.SHA1.String()][StringSubjectNameHash] = util.HashToHex(ca.CACert.RawSubject, sha1.New())
		hashTable[crypto.SHA1.String()][StringSubjectKeyHash] = util.HashToHex(ca.CACert.SubjectKeyId, sha256.New())
		hashTable[crypto.SHA256.String()] = make(map[string]string)
		hashTable[crypto.SHA256.String()][StringSubjectNameHash] = util.HashToHex(ca.CACert.RawSubject, sha256.New())
		hashTable[crypto.SHA256.String()][StringSubjectKeyHash] = util.HashToHex(ca.CACert.SubjectKeyId, sha256.New())
		// Parse period time string
		period, err := time.ParseDuration(v.UpdatePeriod)
		util.CheckError(err)
		if err != nil {
			fmt.Println("Parse time duration failed, using default value. (5s)")
			period, _ = time.ParseDuration("5s")
		}
		// Create a template responder struct
		responder := types.Responder{
			Name:              v.Name,
			Period:            period,
			CACert:            ca.CACert,
			CARawSubject:      ca.CACert.RawSubject,
			CARawSubjectKeyId: ca.CACert.SubjectKeyId,
			SigningCert:       cert,
			SigningSigner:     signer,
			FeatureTable:      featureTable,
			HashTable:         hashTable,
		}

		Responders = append(Responders, responder)
	}
	fmt.Printf("Loaded %d of all responders from database.\n", len(Responders))
}

func loadDistributors() {
	var dbDistributors = make([]types.DbCrlDistributor, 0)
	dao.Find(&dbDistributors)

	if len(dbDistributors) == 0 {
		fmt.Println("There are no distributors in database, stop loading.")
		return
	}

	for _, v := range dbDistributors {
		// Get CertificateAuthorityInfo from database via ID
		caInfo := types.CertificateAuthorityInfo{}
		caInfo.ID = v.CAId
		dao.Find(&caInfo)
		if caInfo.IsEmpty() {
			util.PanicOnError(errors.New("unable to get ca info from database"))
			return
		}
		ca, err := caInfo.ToCA()
		util.PanicOnError(err)
		// Parse period time string
		period, err := time.ParseDuration(v.UpdatePeriod)
		util.CheckError(err)
		if err != nil {
			fmt.Println("Parse time duration failed, using default value. (5s)")
			period, _ = time.ParseDuration("5s")
		}
		util.CheckError(err)
		// Parse raw CRL to x509.RevocationList
		CRL, err := x509.ParseRevocationList(v.RawCRL)
		util.PanicOnError(err)
		distributor := types.Distributor{
			Name:         caInfo.CommonName,
			URIPath:      v.URIPath,
			UpdatePeriod: period,
			CA:           *ca,
			Number:       v.Number,
			CRL:          *CRL,
		}
		Distributors = append(Distributors, distributor)
	}
	fmt.Printf("Loaded %d of all distributors from database.\n", len(Distributors))
}

func printLicense() {
	fmt.Println("Certificate Validation Server (CVS)  Copyright (C) 2023  Levi Marvin (LIU, YUANCHEN)")
	fmt.Println("This program comes with ABSOLUTELY NO WARRANTY; for details read LICENSE.")
	fmt.Println("This is free software, and you are welcome to redistribute it under certain conditions;")
	fmt.Println("Read LICENSE for details.")
}
