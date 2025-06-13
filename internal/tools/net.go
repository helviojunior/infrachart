package tools

import (
    "net"
    "encoding/binary"

    "crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

func IpToUint32(ip net.IP) uint32 {
    ip = ip.To4()
    if ip == nil {
        return 0
    }
    return binary.BigEndian.Uint32(ip)
}

func SubnetToUint32(subNet net.IPNet) uint32 {
	return IpToUint32(subNet.IP)
}

func ParseCertificatePEM(pemData string) (*x509.Certificate, error) {
	pemData = normalizePEM(pemData)
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Println(pemData)
	    return nil, errors.New("Failed to decode PEM block")
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
	    return nil, err
	}

	return parsedCert, nil
}

func normalizePEM(input string) string {
	re := regexp.MustCompile(`(?m)^.*\n`)
	txt := re.ReplaceAllStringFunc(input, func(line string) string {
		if strings.HasPrefix(line, "-----") {
			return "\n" + line // keep newline for header/footer
		}
		return strings.TrimSuffix(line, "\n") // remove newline
	})
	return strings.TrimPrefix(txt, "\n")
}