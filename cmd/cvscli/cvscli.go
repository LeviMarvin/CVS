package main

import (
	"CVS/shared"
	"CVS/types"
	"CVS/util"
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
	"io"
	"os"
	"strconv"
	"time"
)

/*
cvscli - CVS Command-Line Interface tool

Subcommands:
    cert - Manager certificates' status.
    responder - Manager OCSP responders.
    distributor - Manager CRL distributors.
    exec - Execute functions.

Subcommands for subcommands:
    cert list - List all certificates in database.
    cert del - Remove a certificate in database.
    cert import - Import certificate from file into database.
    cert revoke - Revoke a certificate.

    responder add - Add an OCSP responder.
    responder del - Delete an OCSP responder.
    responder set - Set properties of the OCSP responder.
    responder list - List all registered responders.

    distributor add - Add a CRL distributor.
    distributor del - Delete a CRL distributor.
    distributor set - Set properties of the CRL distributor.

    exec gencrl - Generate a new CRL.
*/

var rootCmd = cobra.Command{
	Use:     "cvscli",
	Short:   "CVS Command-Line Interface tool.",
	Long:    "CVS Command-Line Interface tool for control",
	Version: "0.0.0-internal_preview",
	Args:    cobra.ExactArgs(1),
}

// cvscli cert - START
var certCmd = cobra.Command{
	Use:   "cert",
	Short: "",
	Long:  "",
}

var certListCmd = cobra.Command{
	Use:   "list",
	Short: "List all certificates in database.",
	Long:  "Show a list of certificates in database with its ID and content.",
	Run:   runCertListCmd,
}

func runCertListCmd(_ *cobra.Command, _ []string) {
	var certs []*types.CertificateInfo
	dao := shared.GetDAO()
	dao.Find(&certs)
	fmt.Println("[ID]\tSN\tPeriod\tCA\tRevoked")
	for _, cert := range certs {
		sn := hex.EncodeToString(cert.SerialNumber)
		fmt.Printf("[%d]\t%-"+strconv.Itoa(len(sn))+"s\t%-30s\t%-5v\t%-5v\n", cert.ID, sn, cert.NotAfter, cert.IsCA, cert.IsRevoked)
	}
}

var certDelCmd = cobra.Command{
	Use:   "del",
	Short: "Remove a certificate in database.",
	Long:  "Remove a certificate in database, you will never see it again in the database.",
	Run:   runCertDelCmd,
}

func runCertDelCmd(cmd *cobra.Command, _ []string) {}

var certImportCmd = cobra.Command{
	Use:   "import",
	Short: "Import certificate from file into database.",
	Long:  "Import certificate from file into database and index it.",
	Run:   runCertImportCmd,
}

func runCertImportCmd(cmd *cobra.Command, _ []string) {
	path := cmd.Flag("file").Value.String()

	// Input options check
	if path == "" {
		fmt.Println("Invalid command options, please check your input!")
		return
	}

	file, err := os.Open(path)
	util.PanicOnError(err)
	fileBlobs, err := io.ReadAll(file)
	util.PanicOnError(err)
	data, _ := pem.Decode(fileBlobs)
	cert, err := x509.ParseCertificate(data.Bytes)
	util.PanicOnError(err)
	dao := shared.GetDAO()
	util.PanicOnError(err)
	certInfo, err := util.ConvertToCertificateInfo(cert)
	util.PanicOnError(err)

	searchResult := types.CertificateInfo{}
	dao.Find(&searchResult, &certInfo)
	if searchResult.SubjectKeyHash == certInfo.SubjectKeyHash {
		fmt.Println("Duplicate item detected! Abort!")
		return
	}
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
	if (path == "") && (sn == "") {
		fmt.Println("Invalid command options, please check your input!")
		return
	}
	// Parse the reason code and revocation date
	if reason != "" {
		reasonCode, err = strconv.Atoi(reason)
		util.CheckError(err)
		if err != nil {
			fmt.Println("Get reason failed, please check your input.")
		}
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
		certInfo, err := util.ConvertToCertificateInfo(cert)
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

// cvscli responder - START
var responderCmd = cobra.Command{
	Use:   "responder",
	Short: "Responder management command",
	Long:  "Add/Delete/Set responders via this command.",
}

var responderAddCmd = cobra.Command{
	Use:   "add",
	Short: "Add an OCSP responder.",
	Long:  "Add OCSP responder into the database.",
	Run:   runResponderAddCmd,
}

func runResponderAddCmd(cmd *cobra.Command, _ []string) {
	period := cmd.Flag("period").Value.String()
	cacertPath := cmd.Flag("cacert").Value.String()
	certPath := cmd.Flag("cert").Value.String()
	keyPath := cmd.Flag("key").Value.String()
	keyType := cmd.Flag("key_type").Value.String()

	// Input options check
	if (cacertPath == "") || (certPath == "") || (keyPath == "") {
		fmt.Println("Invalid command options, please check your input!")
		return
	}

	// Load CA certificate file
	cacertFile, err := os.Open(cacertPath)
	util.PanicOnError(err)
	cacertFileBlobs, err := io.ReadAll(cacertFile)
	util.PanicOnError(err)
	cacertData, _ := pem.Decode(cacertFileBlobs)
	util.PanicOnError(err)
	cacert, err := x509.ParseCertificate(cacertData.Bytes)
	util.PanicOnError(err)
	// Load signing certificate file
	certFile, err := os.Open(certPath)
	util.PanicOnError(err)
	certFileBlobs, err := io.ReadAll(certFile)
	util.PanicOnError(err)
	certData, _ := pem.Decode(certFileBlobs)
	util.PanicOnError(err)
	// Load signing private key file
	keyFile, err := os.Open(keyPath)
	util.PanicOnError(err)
	keyFileBlobs, err := io.ReadAll(keyFile)
	keyData, _ := pem.Decode(keyFileBlobs)
	util.PanicOnError(err)

	dbResponder := types.DbResponder{
		Model:              gorm.Model{},
		Name:               cacert.Subject.CommonName,
		UpdatePeriod:       period,
		CACertificate:      cacertData.Bytes,
		SigningCertificate: certData.Bytes,
		SigningKey:         keyData.Bytes,
		SigningKeyType:     keyType,
		EnableNonce:        true,
		EnableCutOff:       false,
	}

	tmpResult := types.DbResponder{}

	shared.GetDAO().Save(&dbResponder)
	shared.GetDAO().Find(&tmpResult, &dbResponder)

	if tmpResult.ID == dbResponder.ID {
		fmt.Println("Add responder successfully!")
	}

}

var responderDelCmd = cobra.Command{
	Use:   "del",
	Short: "Delete an OCSP responder.",
	Long:  "",
	Run:   runResponderDelCmd,
}

func runResponderDelCmd(cmd *cobra.Command, _ []string) {
	var dbId int
	var err error
	searchCondition := types.CertificateInfo{}
	searchResult := types.CertificateInfo{}
	inputId := cmd.Flag("id").Value.String()
	inputSn := cmd.Flag("sn").Value.String()
	if inputId == "" && inputSn == "" {
		fmt.Println("Invalid command options, please check your input!")
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

var responderSetCmd = cobra.Command{
	Use:   "set",
	Short: "Set properties of the OCSP responder.",
	Long:  "Set properties of the OCSP responder. Like the enabling status of Nonce, and more.",
	Run:   runResponderSetCmd,
}

func runResponderSetCmd(cmd *cobra.Command, _ []string) {}

var responderListCmd = cobra.Command{
	Use:   "list",
	Short: "List all registered responders.",
	Run:   runResponderListCmd,
}

func runResponderListCmd(_ *cobra.Command, _ []string) {
	var dbResponders []*types.DbResponder
	dao := shared.GetDAO()
	dao.Find(&dbResponders)
	fmt.Println("[ID]\tName\tPeriod")
	for _, responder := range dbResponders {
		fmt.Printf("[%d]\t%"+strconv.Itoa(len(responder.Name))+"s\t%s\n", responder.ID, responder.Name, responder.UpdatePeriod)
	}
}

// cvscli responder - END

var distributorCmd = cobra.Command{
	Use:   "distributor",
	Short: "",
	Long:  "",
}

var execCmd = cobra.Command{
	Use:   "exec",
	Short: "",
	Long:  "",
}

func main() {
	shared.InitSharedStorage()

	// Add subcommands for subcommand "cert"
	certCmd.AddCommand(&certListCmd)
	certCmd.AddCommand(&certDelCmd)
	certImportCmd.Flags().String("file", "", "The file of certificate needed to be imported.")
	certCmd.AddCommand(&certImportCmd)
	certRevokeCmd.Flags().String("file", "", "The file of certificate needed to be revoked.")
	certRevokeCmd.Flags().String("sn", "", "The Serial Number (HEX string) of certificate which needed to be revoked.")
	certRevokeCmd.Flags().String("date", "", "The revocation time, default is now. Format: \"YYYY.MM.DD hh:mm:ss\"")
	certRevokeCmd.Flags().String("reason", "0", "The revocation reason of certificate.")
	certCmd.AddCommand(&certRevokeCmd)
	// Add subcommands for subcommand "responder"
	responderAddCmd.Flags().String("period", "5s", "The response update period (the next response will be generated after this time).")
	responderAddCmd.Flags().String("cacert", "", "The certificate file of the CA to which the responder belongs.")
	responderAddCmd.Flags().String("cert", "", "The PEM-encoded signing certificate file which the responder belongs.")
	responderAddCmd.Flags().String("key", "", "The PEM-encoded PKCS#1 signing private key which the responder belongs.")
	responderAddCmd.Flags().String("key_type", "RSA", "The type of signing private key, only \"RSA\" and \"ECC\" are accepted.")
	responderCmd.AddCommand(&responderAddCmd)
	responderCmd.AddCommand(&responderDelCmd)
	responderCmd.AddCommand(&responderSetCmd)
	responderCmd.AddCommand(&responderListCmd)

	// Add subcommands
	rootCmd.AddCommand(&certCmd)
	rootCmd.AddCommand(&responderCmd)
	rootCmd.AddCommand(&distributorCmd)
	rootCmd.AddCommand(&execCmd)

	err := rootCmd.Execute()
	util.CheckError(err)
}
