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
)

/*
cvscli - CVS Command-Line Interface tool

Subcommands:
    cert - Manager certificates' status.
    responder - Manager OCSP responders.
    distributor - Manager CRL distributors.
    exec - Execute functions.

Subcommands for subcommands:
    cert add - Add a certificate into database.
    cert del - Delete a certificate from database.
    cert import - Import certificate from file into database.
    cert revoke - Revoke a certificate.

    responder add - Add an OCSP responder.
    responder del - Delete an OCSP responder.
    responder set - Set properties of the OCSP responder.

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
	Run:   runCertCmd,
}

func runCertCmd(cmd *cobra.Command, args []string) {}

var certAddCmd = cobra.Command{
	Use:   "add",
	Short: "",
	Long:  "",
	Run:   runCertAddCmd,
}

func runCertAddCmd(cmd *cobra.Command, args []string) {}

var certDelCmd = cobra.Command{
	Use:   "del",
	Short: "",
	Long:  "",
	Run:   runCertDelCmd,
}

func runCertDelCmd(cmd *cobra.Command, args []string) {}

var certImportCmd = cobra.Command{
	Use:   "import",
	Short: "",
	Long:  "",
	Run:   runCertImportCmd,
}

func runCertImportCmd(cmd *cobra.Command, args []string) {
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
	Short: "",
	Long:  "",
	Run:   runCertRevokeCmd,
}

func runCertRevokeCmd(cmd *cobra.Command, args []string) {
	var err error
	path := cmd.Flag("file").Value.String()
	sn := cmd.Flag("sn").Value.String()

	// Input options check
	if (path == "") && (sn == "") {
		fmt.Println("Invalid command options, please check your input!")
		return
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
	Short: "",
	Long:  "",
}

var responderAddCmd = cobra.Command{
	Use:   "add",
	Short: "",
	Long:  "",
	Run:   runResponderAddCmd,
}

func runResponderAddCmd(cmd *cobra.Command, args []string) {
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
	Short: "",
	Long:  "",
	Run:   runResponderDelCmd,
}

func runResponderDelCmd(cmd *cobra.Command, args []string) {}

var responderSetCmd = cobra.Command{
	Use:   "set",
	Short: "",
	Long:  "",
	Run:   runResponderSetCmd,
}

func runResponderSetCmd(cmd *cobra.Command, args []string) {}

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
	certCmd.AddCommand(&certAddCmd)
	certCmd.AddCommand(&certDelCmd)
	certImportCmd.Flags().String("file", "", "The file of certificate needed to be imported.")
	certCmd.AddCommand(&certImportCmd)
	certRevokeCmd.Flags().String("file", "", "The file of certificate needed to be revoked.")
	certRevokeCmd.Flags().String("sn", "", "The Serial Number (HEX string) of certificate which needed to be revoked.")
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

	// Add subcommands
	rootCmd.AddCommand(&certCmd)
	rootCmd.AddCommand(&responderCmd)
	rootCmd.AddCommand(&distributorCmd)
	rootCmd.AddCommand(&execCmd)

	err := rootCmd.Execute()
	util.CheckError(err)
}
