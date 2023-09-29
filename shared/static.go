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
