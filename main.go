package main

import (
	"crypto/x509"
	"debug/pe"
	"encoding/pem"
	"os"
)

func main() {
	ipxe, _ := pe.Open(os.Args[1])

	for _, s := range ipxe.Sections {
		if s.Name == ".rodata" {
			// Load in all of the rodata section
			rodata, _ := s.Data()

			// fmt.Println(hex.Dump(data))

			// Setup interating over rodata
			i := 0
			rodataLength := len(rodata)

			// Iterate over rodata one byte at a time
			for i < rodataLength {
				// Look for the start of ASN.1 SEQUENCE
				if rodata[i] == 0x30 {

					// Calculate the length of the candidate, inoring SEQUENCEs
					// shorter than 127, as it won't contain a meaningful RSA key
					if rodata[i+1] > 127 {
						l := int(rodata[i+1]) - 128

						// We don't care about SEQUENCEs that are longer than a
						// 16 bit integer
						if l <= 2 {

							// Calculate the SEQUENCE lenght
							b := rodata[i+2 : i+2+l]
							sLength := 0
							for _, n := range b {
								sLength += int(n)
								sLength = sLength << 8
							}
							sLength = sLength >> 8

							// Add the SEQUENCE "header" length
							sLength += len(b) + 2

							// We only wont the check SEQUENCEs that fit within the rodata
							if sLength > 0 && sLength+i < rodataLength {
								candidate := rodata[i : sLength+i]

								// Check if we have a public key
								// pub, err := x509.ParsePKIXPublicKey(candidate)
								pub, err := x509.ParseCertificate(candidate)
								if err == nil {
									block := &pem.Block{
										Type:  "CERTIFICATE",
										Bytes: pub.Raw,
									}
									pem.Encode(os.Stdout, block)
								}

								// Check if we have a private key
								_, err = x509.ParsePKCS1PrivateKey(candidate)
								if err == nil {
									block := &pem.Block{
										Type:  "RSA PRIVATE KEY",
										Bytes: candidate,
									}
									pem.Encode(os.Stdout, block)
								}
							}
						}
					}
				}
				i++
			}
		}
	}
}
