package util

import "fmt"

func CheckError(err error) {
    if err != nil {
        fmt.Printf("error: %v\n", err)
        return
    }
}

func PanicOnError(err error) {
    if err != nil {
        panic(err)
    }
}
