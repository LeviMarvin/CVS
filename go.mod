module CVS

go 1.21

require (
	github.com/spf13/cobra v1.7.0
	golang.org/x/crypto v0.14.0
	gorm.io/driver/sqlite v1.5.4
	gorm.io/gorm v1.25.5
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/mattn/go-sqlite3 v1.14.17 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
)

replace golang.org/x/crypto v0.14.0 => github.com/LeviMarvin/go-x-crypto v0.14.0
