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

import "encoding/asn1"

const (
	StringSubjectNameHash = "SubjectNameHash"
	StringSubjectKeyHash  = "SubjectKeyHash"
)

const (
	StringNonce  = "Nonce"
	StringCutoff = "Cutoff"
)

// OidIdPkixOcspNonce id-pkix-ocsp-nonce
var OidIdPkixOcspNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// OidIdPkixOcspCrl id-pkix-ocsp-crl
var OidIdPkixOcspCrl = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 3}

// OidIdPkixOcspArchiveCutoff id-pkix-ocsp-archive-cutoff
var OidIdPkixOcspArchiveCutoff = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 6}

// OidPkixOcspExtendedRevoke id-pkix-ocsp-extended-revoke
var OidPkixOcspExtendedRevoke = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 9}
