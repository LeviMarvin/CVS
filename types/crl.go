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
	"crypto/x509"
	"errors"
	"gorm.io/gorm"
	"time"
)

type Distributor struct {
	Name         string
	URIPath      string
	UpdatePeriod time.Duration
	CA           CertificateAuthority
	Number       int64
	CRL          x509.RevocationList
}

func (distributor *Distributor) UpdateFromDB(db *gorm.DB) error {
	searchedDbDistributor := DbCrlDistributor{}
	db.Find(&searchedDbDistributor, &DbCrlDistributor{Name: distributor.Name})
	if searchedDbDistributor.IsEmpty() {
		return errors.New("unable to find the distributor in database")
	}
	distributor.Number = searchedDbDistributor.Number
	CRL, err := x509.ParseRevocationList(searchedDbDistributor.RawCRL)
	if err != nil {
		return err
	}
	distributor.CRL = *CRL
	return nil
}

func (distributor *Distributor) ToDbDistributor() *DbCrlDistributor {
	dbDistributor := DbCrlDistributor{
		Name:         distributor.Name,
		URIPath:      distributor.URIPath,
		UpdatePeriod: distributor.UpdatePeriod.String(),
		CAId:         distributor.CA.ID,
		Number:       distributor.Number,
		RawCRL:       distributor.CRL.Raw,
	}
	return &dbDistributor
}
