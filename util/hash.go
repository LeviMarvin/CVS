package util

import (
    "encoding/hex"
    "hash"
)

func HashToHex(raw []byte, hash hash.Hash) string {
    hash.Write(raw)
    return hex.EncodeToString(hash.Sum(nil))
}
