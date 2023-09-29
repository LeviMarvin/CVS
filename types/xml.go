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
