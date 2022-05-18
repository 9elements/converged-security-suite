module github.com/9elements/converged-security-suite/v2

go 1.13

require (
	github.com/9elements/converged-security-suite/v2/testdata/firmware v0.0.0-00010101000000-000000000000
	github.com/9elements/go-linux-lowlevel-hw v0.0.0-20220518111144-a82949f8ff5b
	github.com/alecthomas/kong v0.2.11
	github.com/creasty/defaults v1.5.1
	github.com/davecgh/go-spew v1.1.1
	github.com/digitalocean/go-smbios v0.0.0-20180907143718-390a4f403a8e
	github.com/edsrzf/mmap-go v1.0.0
	github.com/fearful-symmetry/gomsr v0.0.1
	github.com/golang-collections/go-datastructures v0.0.0-20150211160725-59788d5eb259
	github.com/google/go-attestation v0.4.0
	github.com/google/go-tpm v0.3.3-0.20210120190357-1ff48daca32f
	github.com/google/uuid v1.3.0
	github.com/klauspost/cpuid/v2 v2.0.9
	github.com/kr/pretty v0.2.1 // indirect
	github.com/linuxboot/contest v0.0.0-20220404120719-d952dfa563c4
	github.com/linuxboot/fiano v1.1.1-0.20220414102525-737513644344
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/marcoguerri/go-tpm-tcti v0.0.0-20210425104733-8e8c8fe68e60
	github.com/steakknife/hamming v0.0.0-20180906055917-c99c65617cd3
	github.com/stretchr/testify v1.7.1
	github.com/tidwall/pretty v1.0.2
	github.com/tjfoc/gmsm v1.4.1
	github.com/ulikunitz/xz v0.5.10
	github.com/xaionaro-facebook/go-dmidecode v0.0.0-20220413144237-c42d5bef2498
	github.com/xaionaro-go/bytesextra v0.0.0-20220103144954-846e454ddea9
	github.com/xaionaro-go/unsafetools v0.0.0-20210722164218-75ba48cf7b3c
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

replace github.com/9elements/converged-security-suite/v2/testdata/firmware => ./testdata/firmware
