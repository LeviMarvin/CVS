# Certificate Validation Server (CVS)
Developed by **Levi Marvin** | Powered by **Go 1.21.1**

**This project is still being developing!**

## Introduction
The Certificate Validation Server (CVS) is an application for PKI system, which used on returning the certificate
validation result to the client.

CVS included two parts: the OCSP Responder and the CRL Distributor. That means CVS could provide CRL and OCSP response.

OCSP Responder supports multi-response for multi-CA in one instance. That means you can use it for your complex PKI
system. Support features like OCSP Nonce, Cutoff.

CRL Distributor will return a certificate revocation list to client. And it will auto process the data with cache.

Notice: CVS is based on SQLite3 as its storage, and there is no plan for supporting any more database system now.

## Usage
There are two important parts: `cvscli` and `server`.

`cvscli` is a Command-Line Interface tool for control CVS, it provides some useful commands.
You can get help with help command. `cvscli help`

`server` is the core of CVS. You can run an instance via this file, including OCSP Responder and CRL Distributor.

CVS used XML config file for storing basic settings. The path is "<executable file>/configs/cvs.xml". Please make sure
this file is existed and correct.

## Development
CVS is using a third-party crypto library (`golang.org/x/crypto`) for advanced functions.
You can find the customized version of x-crypto in [there](https://github.com/LeviMarvin/go-x-crypto).

CVS used these third-party libraries:
- [x-crypto](https://github.com/LeviMarvin/go-x-crypto) (Levi Marvin, **[Official](https://pkg.go.dev/golang.org/x/crypto)**: Google)
- [Gorm](https://gorm.io) (Jinzhu)
- [cobra](https://github.com/spf13/cobra) (spf13)
- and more...