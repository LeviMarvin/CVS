package util

import (
    "crypto/x509/pkix"
    "encoding/asn1"
)

func IsExistsX509Extension(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
    for _, extension := range extensions {
        if extension.Id.Equal(oid) {
            return true
        }
    }
    return false
}
