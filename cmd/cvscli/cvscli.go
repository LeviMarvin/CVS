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

package main

import (
	"CVS/constants"
	"CVS/shared"
	"CVS/types"
	"CVS/util"
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/glebarez/sqlite"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

/*
cvscli - CVS Command-Line Interface tool

Commands:
    ca   - Manage the CAs in database.
    cert - Manage the certificates in database.
    db - Manage the database.
    distributor - Manage CRL distributors.
    responder - Manage OCSP responders.
    exec - Execute functions.

Subcommands:
    ca del - Remove a CA in database.
    ca import - Import a ca into database from files.
    ca list - List all CAs in database.

    cert list - List all certificates in database.
    cert del - Remove a certificate in database.
    cert import - Import certificate from file into database.
    cert revoke - Revoke a certificate.

	db init - Init an empty SQLite3 database file.

    distributor add - Add a CRL distributor.
    distributor del - Delete a CRL distributor.
    distributor set - Set properties of the CRL distributor.
    distributor list - List all registered CRL distributors.

    responder add - Add an OCSP responder.
    responder del - Delete an OCSP responder.
    responder set - Set properties of the OCSP responder.
    responder list - List all registered responders.

Usage example:
*/

var rootCmd = cobra.Command{
	Use:     "cvscli",
	Short:   "CVS Command-Line Interface tool.",
	Long:    "CVS Command-Line Interface tool for control.",
	Version: "V1.0",
	Args:    cobra.ExactArgs(1),
}

// cvscli ca - START
var caCmd = cobra.Command{
	Use:   "ca",
	Short: "CA management command.",
}

var caListCmd = cobra.Command{
	Use:   "list",
	Short: "List all CAs in database.",
	Run:   runCaListCmd,
}

func runCaListCmd(_ *cobra.Command, _ []string) {
	var CAs []*types.CertificateAuthorityInfo
	shared.GetDAO().Find(&CAs)
	if len(CAs) == 0 {
		fmt.Println("There are no CAs in database.")
		return
	}

	fmt.Println("[ID]\tCommonName\tPeriod")
	for _, ca := range CAs {
		cacert, err := x509.ParseCertificate(ca.CertificateBlob)
		util.CheckError(err)
		commonName := cacert.Subject.String()
		//id := hex.EncodeToString(ca.ID)
		fmt.Printf("[%d]\t%-"+strconv.Itoa(len(commonName))+"s\t%-30s\n", ca.ID, commonName, cacert.NotAfter)
	}
}

var caImportCmd = cobra.Command{
	Use:   "import",
	Short: "Import a ca into database from files.",
	Run:   runCaImportCmd,
}

func runCaImportCmd(cmd *cobra.Command, _ []string) {
	var err error
	inputCert := cmd.Flag("cert").Value.String()
	inputKey := cmd.Flag("key").Value.String()
	inputKeyType := cmd.Flag("key_type").Value.String()
	if util.CheckNullableString(inputCert, inputKey, inputKeyType) {
		fmt.Println(constants.NoticeInvalidCommandOptions)
		return
	}
	certFile, err := os.Open(inputCert)
	util.PanicOnError(err)
	cert, err := util.DecodePEMCertificateFile(certFile)
	keyFile, err := os.Open(inputKey)
	util.PanicOnError(err)
	keyFileBlobs, err := io.ReadAll(keyFile)
	util.PanicOnError(err)
	keyData, _ := pem.Decode(keyFileBlobs)
	dao := shared.GetDAO()
	caInfo := types.CertificateAuthorityInfo{
		CommonName:      cert.Subject.CommonName,
		RawSubject:      cert.RawSubject,
		SubjectKeyHash:  util.HashToHex(cert.RawSubjectPublicKeyInfo, sha1.New()),
		RawIssuerName:   cert.RawIssuer,
		RawSubjectName:  cert.RawSubject,
		CertificateBlob: cert.Raw,
		KeyBlob:         keyData.Bytes,
		KeyType:         inputKeyType,
	}
	dao.Save(&caInfo)

}

var caDelCmd = cobra.Command{
	Use:   "del",
	Short: "Remove a CA in database, you will never see it again in the database.",
	Run:   runCaDelCmd,
}

func runCaDelCmd(cmd *cobra.Command, _ []string) {
	var dbId int
	searchCondition := types.CertificateAuthorityInfo{}
	searchResult := types.CertificateAuthorityInfo{}
	inputId := cmd.Flag("id").Value.String()
	if util.CheckNullableString(inputId) {
		fmt.Println(constants.NoticeInvalidCommandOptions)
		return
	}
	dbId, err := strconv.Atoi(inputId)
	util.PanicOnError(err)
	searchCondition.ID = uint(dbId)
	dao := shared.GetDAO()
	tx := dao.Find(&searchResult, &searchCondition)
	if !searchResult.IsEmpty() {
		if searchResult.ID == searchCondition.ID {
			tx.Delete(&searchResult)
		}
	}
}

// cvscli ca - END

// cvscli cert - START
var certCmd = cobra.Command{
	Use:   "cert",
	Short: "Certificate management command.",
}

var certListCmd = cobra.Command{
	Use:   "list",
	Short: "List all certificates in database.",
	Long:  "Show a list of certificates in database with its ID and content.",
	Run:   runCertListCmd,
}

func runCertListCmd(_ *cobra.Command, _ []string) {
	var certs []*types.CertificateInfo
	shared.GetDAO().Find(&certs)
	if len(certs) == 0 {
		fmt.Println("There are no certificates in database.")
		return
	}
	fmt.Println("[ID]\tCA_ID\tSN\tPeriod\tIsCA\tRevoked")
	for _, cert := range certs {
		sn := hex.EncodeToString(cert.SerialNumber)
		fmt.Printf("[%d]\t%d\t%-"+strconv.Itoa(len(sn))+"s\t%-30s\t%-5v\t%-5v\n", cert.ID, cert.CAId, sn, cert.NotAfter, cert.IsCA, cert.IsRevoked)
	}
}

var certDelCmd = cobra.Command{
	Use:   "del",
	Short: "Remove a certificate in database.",
	Long:  "Remove a certificate in database, you will never see it again in the database.",
	Run:   runCertDelCmd,
}

func runCertDelCmd(cmd *cobra.Command, _ []string) {
	var dbId int
	var err error
	searchCondition := types.CertificateInfo{}
	searchResult := types.CertificateInfo{}
	inputId := cmd.Flag("id").Value.String()
	inputSn := cmd.Flag("sn").Value.String()
	if inputId == "" && inputSn == "" {
		fmt.Println(constants.NoticeInvalidCommandOptions)
		return
	}
	if inputId != "" {
		dbId, err = strconv.Atoi(inputId)
		if err != nil {
			fmt.Println("Convert inputted ID to int failed, please check your input.")
			return
		}
		searchCondition.ID = uint(dbId)
	}
	if inputSn != "" {
		rawSn, err := hex.DecodeString(inputSn)
		if err != nil {
			fmt.Println("Convert inputted SN to bytes failed, please check your input.")
			return
		}
		searchCondition.SerialNumber = rawSn
	}
	dao := shared.GetDAO()
	tx := dao.Find(&searchResult, &searchCondition)
	if !searchResult.IsEmpty() {
		if searchResult.ID == searchCondition.ID {
			tx.Delete(&searchResult)
		}
	}
}

var certImportCmd = cobra.Command{
	Use:   "import",
	Short: "Import certificate from file into database.",
	Long:  "Import certificate from file into database and index it.",
	Run:   runCertImportCmd,
}

func runCertImportCmd(cmd *cobra.Command, _ []string) {
	inputFile := cmd.Flag("file").Value.String()

	// Input options check
	if util.CheckNullableString(inputFile) {
		fmt.Println(constants.NoticeInvalidCommandOptions)
		return
	}

	file, err := os.Open(inputFile)
	util.PanicOnError(err)
	cert, err := util.DecodePEMCertificateFile(file)
	util.PanicOnError(err)
	dao := shared.GetDAO()
	util.PanicOnError(err)
	certInfo, err := types.ConvertToBasicCertificateInfo(cert)
	util.PanicOnError(err)

	searchResult := types.CertificateInfo{}
	dao.Find(&searchResult, &certInfo)
	if searchResult.SubjectKeyHash == certInfo.SubjectKeyHash {
		fmt.Println("Duplicate item detected! Abort!")
		return
	}

	caId, err := types.FetchCertIssuerID(cert, shared.GetDAO())
	if caId == 0 {
		util.CheckError(err)
	}
	certInfo.CAId = caId
	dao.Save(&certInfo)

	fmt.Println("Import certificate successfully!")
	testResult := types.CertificateInfo{}
	dao.Find(&testResult, &certInfo)
	fmt.Printf("Recorded: %+v\n", testResult)
}

var certRevokeCmd = cobra.Command{
	Use:   "revoke",
	Short: "Revoke an certificate",
	Long:  "Revoke an certificate with date and reason",
	Run:   runCertRevokeCmd,
}

func runCertRevokeCmd(cmd *cobra.Command, _ []string) {
	var err error
	var reasonCode int
	var revocationTime time.Time
	path := cmd.Flag("file").Value.String()
	sn := cmd.Flag("sn").Value.String()
	date := cmd.Flag("date").Value.String()
	reason := cmd.Flag("reason").Value.String()

	// Input options check
	if path == "" && sn == "" {
		fmt.Println(constants.NoticeInvalidCommandOptions)
		return
	}
	// Parse the reason code and revocation date
	if reason != "" {
		reasonCode, err = strconv.Atoi(reason)
		util.CheckError(err)
		if err != nil {
			fmt.Println("Get the revocation reason from code failed, please check your input.")
		}
	} else {
		reasonCode = 0
	}
	if date != "" {
		revocationTime, err = time.Parse("2006.01.02 15:04:05", date)
		util.CheckError(err)
		if err != nil {
			fmt.Println("Get time failed, please check your input.")
		}
	} else {
		revocationTime = time.Now()
	}

	dao := shared.GetDAO()
	util.PanicOnError(err)
	if path != "" {
		file, err := os.Open(path)
		util.PanicOnError(err)
		fileBlobs, err := io.ReadAll(file)
		fileData, _ := pem.Decode(fileBlobs)
		cert, err := x509.ParseCertificate(fileData.Bytes)
		util.PanicOnError(err)
		certInfo, err := types.ConvertToBasicCertificateInfo(cert)
		util.PanicOnError(err)
		searchResult := types.CertificateInfo{}
		dao.Find(&searchResult, &certInfo)
		if searchResult.SubjectKeyHash == certInfo.SubjectKeyHash {
			searchResult.IsRevoked = true
			searchResult.RevocationTime = revocationTime
			searchResult.RevocationReason = reasonCode
			dao.Where(&certInfo).Updates(&searchResult)
			tmpResult := types.CertificateInfo{}
			dao.Find(&tmpResult, &searchResult)
			if tmpResult.IsRevoked == true {
				fmt.Println("Revoke certificate successfully!")
			}
		}
	} else if sn != "" {
		searchResult := types.CertificateInfo{}
		byteSN, err := hex.DecodeString(sn)
		util.CheckError(err)
		dao.Find(&searchResult, types.CertificateInfo{SerialNumber: byteSN})
		if bytes.Equal(searchResult.SerialNumber, byteSN) {
			newItem := searchResult
			newItem.IsRevoked = true
			newItem.RevocationTime = revocationTime
			newItem.RevocationReason = reasonCode
			dao.Where(&searchResult).Updates(&newItem)
			tmpResult := types.CertificateInfo{}
			dao.Find(&tmpResult, &newItem)
			if tmpResult.IsRevoked == true {
				fmt.Println("Revoke certificate successfully!")
			}
		}
	}

}

// cvscli cert - END

// cvscli db - START
var dbCmd = cobra.Command{
	Use:   "db",
	Short: "Manage the database",
	Long:  "Manage the database",
}

var dbInitCmd = cobra.Command{
	Use:   "init",
	Short: "Initialize the database.",
	Run:   runDbInitCmd,
}

func runDbInitCmd(cmd *cobra.Command, _ []string) {
	var err error
	dao, err := gorm.Open(sqlite.Open(shared.ConfigRoot.Database.FilePath), &gorm.Config{})
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

// cvscli db - END

// cvscli distributor - START
var distributorCmd = cobra.Command{
	Use:   "distributor",
	Short: "The CRL Distributor management command",
	Long:  "Add/Delete/Set the CRL distributors via this command",
}

var distributorAddCmd = cobra.Command{
	Use:   "add",
	Short: "Add a CRL distributor.",
	Long:  "Add a CRL distributor via this command",
	Run:   runDistributorAddCmd,
}

func runDistributorAddCmd(cmd *cobra.Command, _ []string) {
	inputCAId := cmd.Flag("caid").Value.String()
	inputURI := cmd.Flag("uri").Value.String()
	inputPeriod := cmd.Flag("period").Value.String()
	if util.CheckNullableString(inputURI, inputCAId, inputPeriod) {
		fmt.Println("Invalid command options, please check your input!")
		return
	}
	caid, err := strconv.Atoi(inputCAId)
	util.CheckError(err)
	// Get the CA
	caInfo := types.CertificateAuthorityInfo{}
	caInfo.ID = uint(caid)
	shared.GetDAO().Find(&caInfo)
	if caInfo.IsEmpty() {
		fmt.Println("Unable to get the CA in database.")
		return
	}
	ca, err := caInfo.ToCA()
	util.CheckError(err)

	dbDistributor := types.DbCrlDistributor{
		Name:         ca.Name,
		URIPath:      inputURI,
		UpdatePeriod: inputPeriod,
		CAId:         uint(caid),
		Number:       0,
	}
	// Parse period time string
	period, err := time.ParseDuration(inputPeriod)
	util.CheckError(err)
	if err != nil {
		fmt.Println("Parse time duration failed, using default value. (5s)")
		period, _ = time.ParseDuration("5s")
	}
	// Create the basic CRL
	CRL, err := ca.CreateBasicCRL(*ca.FetchRevokedEntries(shared.GetDAO()), dbDistributor.Number, period, x509.SHA256WithRSA)
	dbDistributor.RawCRL = CRL.Raw
	shared.GetDAO().Save(&dbDistributor)
	tmpDistributor := types.DbCrlDistributor{}
	shared.GetDAO().Find(&tmpDistributor, &dbDistributor)
	if !tmpDistributor.IsEmpty() {
		fmt.Println("Add distributor successfully!")
	} else {
		fmt.Println("Add distributor failed!")
	}
}

var distributorDelCmd = cobra.Command{
	Use:   "del",
	Short: "Delete a CRL distributor.",
	Long:  "Delete a CRL distributor via this command.",
	Run:   runDistributorDelCmd,
}

func runDistributorDelCmd(cmd *cobra.Command, _ []string) {
	inputId := cmd.Flag("id").Value.String()
	if util.CheckNullableString(inputId) {
		fmt.Println("Invalid command options, please check your input!")
		return
	}

	id, err := strconv.Atoi(inputId)
	util.CheckError(err)
	searchResult := types.DbCrlDistributor{}
	searchResult.ID = uint(id)

	dao := shared.GetDAO()
	tx := dao.Find(&searchResult)
	if !searchResult.IsEmpty() {
		tx.Delete(&searchResult)
	}
}

var distributorSetCmd = cobra.Command{
	Use:   "set",
	Short: "Set properties of the CRL distributor.",
	Long:  "Set properties of the CRL distributor via this command.",
	Run:   runDistributorSetCmd,
}

func runDistributorSetCmd(cmd *cobra.Command, _ []string) {
	inputCAId := cmd.Flag("caid").Value.String()
	inputId := cmd.Flag("id").Value.String()
	inputPeriod := cmd.Flag("period").Value.String()
	inputURI := cmd.Flag("uri").Value.String()
	if util.CheckNullableString(inputId) {
		fmt.Println(constants.NoticeInvalidCommandOptions)
		return
	}
	id, err := strconv.Atoi(inputId)
	util.PanicOnError(err)
	distributor := types.DbCrlDistributor{}
	distributor.ID = uint(id)
	shared.GetDAO().Find(&distributor)
	if distributor.IsEmpty() {
		fmt.Println("Unable to get the distributor in database.")
		return
	}
	newDistributor := distributor
	if inputCAId != "" {
		caid, err := strconv.Atoi(inputId)
		util.PanicOnError(err)
		newDistributor.CAId = uint(caid)
	}
	if inputPeriod != "" {
		newDistributor.UpdatePeriod = inputPeriod
	}
	if inputURI != "" {
		newDistributor.URIPath = inputURI
	}
	shared.GetDAO().Where(&distributor).Updates(&newDistributor)

}

var distributorListCmd = cobra.Command{
	Use:   "list",
	Short: "List all registered CRL distributors.",
	Long:  "List all registered CRL distributors via this command.",
	Run:   runDistributorListCmd,
}

func runDistributorListCmd(_ *cobra.Command, _ []string) {
	var distributors []types.DbCrlDistributor
	shared.GetDAO().Find(&distributors)
	if len(distributors) == 0 {
		fmt.Println("There are no registered CRL distributors.")
		return
	}
	fmt.Println("[ID]\tName\tCA(ID)\tPeriod")
	for _, distributor := range distributors {
		fmt.Printf("[%d]\t%"+strconv.Itoa(len(distributor.Name))+"s\t%d\t%s\n", distributor.ID, distributor.Name, distributor.CAId, distributor.UpdatePeriod)
	}
}

// cvscli distributor - END

// cvscli responder - START
var responderCmd = cobra.Command{
	Use:   "responder",
	Short: "The OCSP Responders management command",
	Long:  "Add/Delete/Set responders via this command.",
}

var responderAddCmd = cobra.Command{
	Use:   "add",
	Short: "Add an OCSP responder.",
	Long:  "Add OCSP responder into the database.",
	Run:   runResponderAddCmd,
}

func runResponderAddCmd(cmd *cobra.Command, _ []string) {
	inputCAId := cmd.Flag("caid").Value.String()
	inputCert := cmd.Flag("cert").Value.String()
	inputKey := cmd.Flag("key").Value.String()
	inputKeyType := cmd.Flag("key_type").Value.String()
	inputPeriod := cmd.Flag("period").Value.String()

	// Input options check
	if util.CheckNullableString(inputCAId, inputCert, inputKey, inputKeyType, inputPeriod) {
		fmt.Println(constants.NoticeInvalidCommandOptions)
		return
	}

	// Convert the string type caid into int
	caId, err := strconv.Atoi(inputCAId)
	util.PanicOnError(err)
	// Get the CA
	caInfo := types.CertificateAuthorityInfo{}
	caInfo.ID = uint(caId)
	shared.GetDAO().Find(&caInfo)
	if caInfo.CommonName == "" {
		fmt.Println("Unable to get the CA in database.")
		return
	}
	ca, err := caInfo.ToCA()
	util.CheckError(err)

	// Load signing certificate file
	certFile, err := os.Open(inputCert)
	util.PanicOnError(err)
	cert, err := util.DecodePEMCertificateFile(certFile)
	util.PanicOnError(err)
	// Load signing private key file
	keyFile, err := os.Open(inputKey)
	util.PanicOnError(err)
	keyFileBlobs, err := io.ReadAll(keyFile)
	keyData, _ := pem.Decode(keyFileBlobs)
	util.PanicOnError(err)

	dbResponder := types.DbResponder{
		Model:              gorm.Model{},
		Name:               ca.CACert.Subject.CommonName,
		UpdatePeriod:       inputPeriod,
		CAId:               uint(caId),
		SigningCertificate: cert.Raw,
		SigningKey:         keyData.Bytes,
		SigningKeyType:     inputKeyType,
		EnableNonce:        true,
		EnableCutOff:       false,
		EnableCrlEntry:     false,
	}

	tmpResult := types.DbResponder{}

	shared.GetDAO().Save(&dbResponder)
	shared.GetDAO().Find(&tmpResult, &dbResponder)

	if !tmpResult.IsEmpty() {
		fmt.Println("Add responder successfully!")
	} else {
		fmt.Println("Add responder failed!")
	}
}

var responderDelCmd = cobra.Command{
	Use:   "del",
	Short: "Delete an OCSP responder.",
	Long:  "Delete an OCSP responder with its ID.",
	Run:   runResponderDelCmd,
}

func runResponderDelCmd(cmd *cobra.Command, _ []string) {
	var dbId int
	var err error
	inputId := cmd.Flag("id").Value.String()
	if util.CheckNullableString(inputId) {
		fmt.Println(constants.NoticeInvalidCommandOptions)
		return
	}
	dbId, err = strconv.Atoi(inputId)
	util.PanicOnError(err)
	responder := types.DbResponder{}
	responder.ID = uint(dbId)

	shared.GetDAO().Find(&responder)
	if !responder.IsEmpty() {
		shared.GetDAO().Delete(&responder)
	}
}

var responderSetCmd = cobra.Command{
	Use:   "set",
	Short: "Set properties of the OCSP responder.",
	Long:  "Set properties of the OCSP responder. Like the enabling status of Nonce, and more.",
	Run:   runResponderSetCmd,
}

func runResponderSetCmd(cmd *cobra.Command, _ []string) {
	var err error
	crlentry, err := cmd.Flags().GetBool("crlentry")
	cutoff, err := cmd.Flags().GetBool("cutoff")
	inputCAId := cmd.Flag("caid").Value.String()
	inputCert := cmd.Flag("cert").Value.String()
	inputId := cmd.Flag("id").Value.String()
	inputKey := cmd.Flag("key").Value.String()
	inputKeyType := cmd.Flag("key_type").Value.String()
	inputPeriod := cmd.Flag("period").Value.String()
	nonce, err := cmd.Flags().GetBool("nonce")

	if util.CheckNullableString(inputId) {
		fmt.Println(constants.NoticeInvalidCommandOptions)
		return
	}

	// Convert the string type id and caid into int
	id, err := strconv.Atoi(inputId)
	util.PanicOnError(err)
	caId, err := strconv.Atoi(inputCAId)
	util.PanicOnError(err)

	// Get the CA
	caInfo := types.CertificateAuthorityInfo{}
	caInfo.ID = uint(caId)
	shared.GetDAO().Find(&caInfo)
	if caInfo.CommonName == "" {
		fmt.Println("Unable to get the CA in database.")
		return
	}
	ca, err := caInfo.ToCA()
	util.CheckError(err)

	// Load signing certificate file
	certFile, err := os.Open(inputCert)
	util.PanicOnError(err)
	cert, err := util.DecodePEMCertificateFile(certFile)
	util.PanicOnError(err)
	// Load signing private key file
	keyFile, err := os.Open(inputKey)
	util.PanicOnError(err)
	keyFileBlobs, err := io.ReadAll(keyFile)
	keyData, _ := pem.Decode(keyFileBlobs)
	util.PanicOnError(err)

	searchCondition := types.DbResponder{}
	searchResult := types.DbResponder{}
	if inputId != "" {
		id, err = strconv.Atoi(inputId)
		util.PanicOnError(err)
		searchCondition.ID = uint(id)
	}
	dao := shared.GetDAO()
	tx := dao.Find(&searchResult, &searchCondition)
	if !searchResult.IsEmpty() {
		if searchResult.ID == searchCondition.ID {
			searchResult.CAId = uint(caId)
			searchResult.EnableCrlEntry = crlentry
			searchResult.EnableCutOff = cutoff
			searchResult.EnableNonce = nonce
			searchResult.Name = ca.CACert.Subject.CommonName
			searchResult.SigningCertificate = cert.Raw
			searchResult.SigningKey = keyData.Bytes
			searchResult.SigningKeyType = inputKeyType
			searchResult.UpdatePeriod = inputPeriod
			tx.Updates(searchResult)
		}
	}
}

var responderListCmd = cobra.Command{
	Use:   "list",
	Short: "List all registered responders.",
	Run:   runResponderListCmd,
}

func runResponderListCmd(_ *cobra.Command, _ []string) {
	var responders []*types.DbResponder
	shared.GetDAO().Find(&responders)
	if len(responders) == 0 {
		fmt.Println("There are no registered OCSP responders.")
		return
	}
	fmt.Println("[ID]\tName\tPeriod")
	for _, responder := range responders {
		fmt.Printf("[%d]\t%"+strconv.Itoa(len(responder.Name))+"s\t%s\n", responder.ID, responder.Name, responder.UpdatePeriod)
	}
}

// cvscli responder - END

var execCmd = cobra.Command{
	Use:   "exec",
	Short: "",
	Long:  "",
}

func main() {
	shared.InitSharedStorage()

	// Add subcommands for command "ca"
	caDelCmd.Flags().StringP("id", "i", "", "The database ID of the CA which you want to delete.")
	caCmd.AddCommand(&caDelCmd)
	caImportCmd.Flags().StringP("cert", "c", "", "The file of certificate needed to be imported.")
	caImportCmd.Flags().StringP("key", "k", "", "The PEM-encoded PKCS#1 private key of CA needed to be imported.")
	caImportCmd.Flags().StringP("key_type", "t", "RSA", "The type of signing private key, only \"RSA\" and \"ECC\" are accepted.")
	caCmd.AddCommand(&caImportCmd)
	caCmd.AddCommand(&caListCmd)
	// Add subcommands for command "cert"
	certDelCmd.Flags().StringP("id", "i", "", "The ID of certificate witch need to be deleted.")
	certDelCmd.Flags().StringP("sn", "n", "", "The serial number of certificate witch need to be deleted.")
	certCmd.AddCommand(&certDelCmd)
	certImportCmd.Flags().StringP("file", "f", "", "The file of certificate needed to be imported.")
	certCmd.AddCommand(&certImportCmd)
	certRevokeCmd.Flags().StringP("date", "d", "", "The revocation time, default is now. Format: \"YYYY.MM.DD hh:mm:ss\"")
	certRevokeCmd.Flags().StringP("file", "f", "", "The file of certificate needed to be revoked.")
	certRevokeCmd.Flags().StringP("reason", "r", "0", "The revocation reason of certificate.")
	certRevokeCmd.Flags().StringP("sn", "n", "", "The serial number (HEX string) of certificate which needed to be revoked.")
	certCmd.AddCommand(&certListCmd)
	certCmd.AddCommand(&certRevokeCmd)
	// Add subcommands for command "db"
	dbCmd.AddCommand(&dbInitCmd)
	// Add subcommands for command "distributor"
	distributorAddCmd.Flags().StringP("caid", "i", "", "The database ID of CA which the responder belongs.")
	distributorAddCmd.Flags().StringP("period", "p", "24h", "The CRL update period (the next CRL will be generated after this time). Only hours/minutes/seconds are supported.")
	distributorAddCmd.Flags().StringP("uri", "u", "/default.crl", "The URI path for fetching the CRL.")
	distributorCmd.AddCommand(&distributorAddCmd)
	distributorDelCmd.Flags().StringP("id", "i", "", "The database ID of the distributor which you want to remove.")
	distributorCmd.AddCommand(&distributorDelCmd)
	distributorSetCmd.Flags().StringP("id", "i", "", "The database ID of the distributor which you want to set.")
	distributorSetCmd.Flags().StringP("caid", "c", "", "The database ID of CA which the responder belongs.")
	distributorSetCmd.Flags().StringP("period", "p", "", "The CRL update period (the next CRL will be generated after this time).")
	distributorSetCmd.Flags().StringP("uri", "u", "", "The URI path for fetching the CRL.")
	distributorCmd.AddCommand(&distributorSetCmd)
	distributorCmd.AddCommand(&distributorListCmd)
	// Add subcommands for command "responder"
	responderAddCmd.Flags().StringP("caid", "i", "", "The database ID of CA which the responder belongs.")
	responderAddCmd.Flags().StringP("cert", "c", "", "The PEM-encoded signing certificate file which the responder belongs.")
	responderAddCmd.Flags().StringP("key", "k", "", "The PEM-encoded PKCS#1 signing private key which the responder belongs.")
	responderAddCmd.Flags().StringP("key_type", "t", "RSA", "The type of signing private key, only \"RSA\" and \"ECC\" are accepted.")
	responderAddCmd.Flags().StringP("period", "p", "5s", "The response update period (the next response will be generated after this time).")
	responderCmd.AddCommand(&responderAddCmd)
	responderDelCmd.Flags().StringP("id", "i", "", "The database ID of responder witch need to be deleted.")
	responderCmd.AddCommand(&responderDelCmd)
	responderSetCmd.Flags().StringP("caid", "", "", "The database ID of CA which the responder belongs.")
	responderSetCmd.Flags().StringP("cert", "c", "", "The PEM-encoded signing certificate file which the responder belongs.")
	responderSetCmd.Flags().BoolP("cutoff", "a", false, "Control enable/disable the Archive Cutoff. (Default: FALSE)")
	responderSetCmd.Flags().BoolP("crlentry", "", false, "Control enable/disable the CRL Entry. (Default: FALSE)")
	responderSetCmd.Flags().StringP("id", "i", "", "The database ID of responder witch need to be deleted.")
	responderSetCmd.Flags().StringP("key", "k", "", "The PEM-encoded PKCS#1 signing private key which the responder belongs.")
	responderSetCmd.Flags().StringP("key_type", "t", "RSA", "The type of signing private key, only \"RSA\" and \"ECC\" are accepted.")
	responderSetCmd.Flags().BoolP("nonce", "n", true, "Control enable/disable the Nonce. (Default: TRUE)")
	responderSetCmd.Flags().StringP("period", "p", "5s", "The response update period (the next response will be generated after this time).")
	responderCmd.AddCommand(&responderListCmd)
	responderCmd.AddCommand(&responderSetCmd)

	// Add subcommands
	rootCmd.AddCommand(&caCmd)
	rootCmd.AddCommand(&certCmd)
	rootCmd.AddCommand(&dbCmd)
	rootCmd.AddCommand(&distributorCmd)
	rootCmd.AddCommand(&responderCmd)
	rootCmd.AddCommand(&execCmd)

	err := rootCmd.Execute()
	util.CheckError(err)
}
