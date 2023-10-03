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

import "encoding/xml"

type CVS struct {
	XMLName   xml.Name  `xml:"cvs"`
	Database  _database `xml:"database"`
	Functions _function `xml:"function"`
}

type _database struct {
	XMLName  xml.Name `xml:"database"`
	FilePath string   `xml:"file"`
}

type _function struct {
	XMLName xml.Name `xml:"function"`
	OCSP    _ocsp    `xml:"ocsp"`
	CRL     _crl     `xml:"crl"`
}

type _ocsp struct {
	XMLName  xml.Name `xml:"ocsp"`
	IsEnable bool     `xml:"enable"`
	Address  string   `xml:"address"`
	Port     int      `xml:"port"`
}

type _crl struct {
	XMLName  xml.Name `xml:"crl"`
	IsEnable bool     `xml:"enable"`
	Address  string   `xml:"address"`
	Port     int      `xml:"port"`
}
