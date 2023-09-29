package main

import (
    "CVS/responder"
    "CVS/shared"
    "CVS/util"
    "net/http"
)

func main() {
    shared.InitSharedStorage()
    go runOcspResponder()
    go runCrlDistributor()
    select {}
}

func runOcspResponder() {

    // Start Listener
    mux := http.NewServeMux()
    mux.HandleFunc("/", responder.HttpIndexHandler)
    err := http.ListenAndServe(shared.OcspRspAddress, mux)
    util.PanicOnError(err)
}

func runCrlDistributor() {
}
