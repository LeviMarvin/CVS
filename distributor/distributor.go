package distributor

import (
	"CVS/shared"
	"CVS/types"
	"CVS/util"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func CrlHttpIndexHandler(w http.ResponseWriter, r *http.Request) {
	// Parse received request
	err := r.ParseForm()
	util.CheckError(err)
	if len(shared.Distributors) == 0 {
		util.CheckError(errors.New(""))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(nil)
	}
	fmt.Printf("Received request for the URI: %s\n", r.RequestURI)

	distributor, err := FetchMatchedDistributor(r.RequestURI)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(nil)
		return
	}

	// Regenerate the CRL if it was expired.
	timeNow := time.Now().UTC()
	if timeNow.After(distributor.CRL.NextUpdate) {
		fmt.Println(fmt.Sprintf("Requested CRL has expired (%v, time now: %v), generate a new one.", distributor.CRL.NextUpdate, timeNow))
		var err error
		// Get the original DbDistributor struct for searching
		dbDistributor := distributor.ToDbDistributor()
		// Get revoked certificates of the CA
		revocationEntries := distributor.CA.FetchRevokedEntries(shared.GetDAO())
		// Set the CRL number of the new CRL
		newCRLNumber := dbDistributor.Number + 1
		// Create the new CRL
		newCRL, err := distributor.CA.CreateBasicCRL(*revocationEntries, newCRLNumber, distributor.UpdatePeriod, x509.SHA256WithRSA)
		util.CheckError(err)
		// Save the new DbDistributor with the new CRL into the database
		newDbDistributor := types.DbCrlDistributor{
			Name:         dbDistributor.Name,
			URIPath:      dbDistributor.URIPath,
			UpdatePeriod: dbDistributor.UpdatePeriod,
			CAId:         dbDistributor.CAId,
			Number:       newCRLNumber,
			RawCRL:       newCRL.Raw,
		}
		shared.GetDAO().Where(&dbDistributor).Updates(&newDbDistributor)
		// Update this distributor
		//err = distributor.UpdateFromDB(shared.GetDAO())
		//util.CheckError(err)
		distributor.Number = newCRLNumber
		distributor.CRL = *newCRL
	}

	//w.Header().Set("Content-Type", "Application Data")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(distributor.CRL.Raw)
}

func FetchMatchedDistributor(URI string) (*types.Distributor, error) {
	if len(shared.Distributors) == 0 {
		return nil, errors.New("this error should not be happened, there are no distributors in shared storage")
	}

	for _, distributor := range shared.Distributors {
		if strings.Contains(URI, distributor.URIPath) {
			return &distributor, nil
		}
	}

	return nil, errors.New("no matched distributor found")
}
