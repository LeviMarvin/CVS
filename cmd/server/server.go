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
	"CVS/distributor"
	"CVS/responder"
	"CVS/shared"
	"CVS/util"
	"errors"
	"net/http"
)

func main() {
	shared.InitSharedStorage()
	go runOcspResponder()
	go runCrlDistributor()
	select {}
}

func runOcspResponder() {
	// Check responders
	if len(shared.Responders) == 0 {
		util.CheckError(errors.New("no responders, but the responder function enabled"))
		return
	}
	// Start Listener
	mux := http.NewServeMux()
	mux.HandleFunc("/", responder.OcspHttpIndexHandler)
	err := http.ListenAndServe(shared.OcspRspAddress, mux)
	util.PanicOnError(err)
}

func runCrlDistributor() {
	// Check distributors
	if len(shared.Distributors) == 0 {
		util.CheckError(errors.New("no distributors, but the distribution function enabled"))
		return
	}
	// Start Listener
	mux := http.NewServeMux()
	mux.HandleFunc("/", distributor.CrlHttpIndexHandler)
	err := http.ListenAndServe(shared.CrlDistAddress, mux)
	util.PanicOnError(err)
}
