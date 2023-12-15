数字证书有效性服务器软件（简称“CVS”）由著作权人刘垣辰独立开发，现著作权人刘垣辰正申请中华人民共和国软件著作权，为证明此开源平台账号为刘垣辰本人所有与使用，在本项目位于 GitHub 开源平台上开源页面的首页添加此行文本，特此证明。
# Certificate Validation Server (CVS)
Developed by **Levi Marvin** | Powered by **Go 1.21.1**

Open source under the GPLv3 license.

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
You can get help with the help command (`cvscli help`).

`server` is the core of CVS. You can run an instance via this file, including OCSP Responder and CRL Distributor.

CVS used XML config file for storing basic settings. The path is "<executable file>/configs/cvs.xml". Please make sure
this file is existed and correct.

### `cvscli`
cvscli supports those commands:
- `ca` To manage the CAs in database.
- `cert` To manage the certificates in database.
- `db` To manage the database.
- `distributor` To manage CRL distributors.
- `responder` To manage OCSP responders.

You can get the helps of commands via the `help` subcommand or `-h`/`--help` options.

### `server`
You can run this program to start an instance of CVS.

### `configs/cvs.xml`
This file is the core config of CVS, you can control the status of OCSP Responder and CRL Distributor,
also include controlling the database.

*The password of database has not been supported.*

The server of CVS will auto binds the addresses in the config file. Please make sure the addresses are available.

## Development
**This project is still being developing! New features will be added in the future.**

The progress of coding:

- [x] Basic OCSP Responder
- [x] Basic CRL Distributor
- [ ] Full extensions support for OCSP Responder
- [ ] Full types and extensions support for CRL Distributor

CVS is using a third-party crypto library (`golang.org/x/crypto`) for advanced functions.
You can find the customized version of x-crypto in [there](https://github.com/LeviMarvin/go-x-crypto).

CVS used these third-party libraries:
- [x-crypto](https://github.com/LeviMarvin/go-x-crypto) (Levi Marvin, **[Official](https://pkg.go.dev/golang.org/x/crypto)**: Google)
- [Gorm](https://gorm.io) (Jinzhu)
- [cobra](https://github.com/spf13/cobra) (spf13)
- and more...
