package models

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"

    "sort"

	"github.com/helviojunior/infrachart/internal/tools"
)

type NoDataError struct {
	Message string
}

func (e NoDataError) Error() string {
	return e.Message
}

type Cert struct {
    ID string
    CN string
    SelfSigned bool
    AlternateNames []string
}

func (cert *Cert) String() string {
    return fmt.Sprintf("%s <%s>", cert.CN, cert.ID)
}

func (cert *Cert) Hash() string {
    var hash string
    sort.Strings(cert.AlternateNames)
    //_calcHash(&hash, cert.ID, cert.CN, cert.AlternateNames)
    _calcHash(&hash, cert.CN, cert.AlternateNames)

    return hash
}

type SubnetEntry struct {
    Subnet string
    Hosts  []*HostEntry
}

func (net *SubnetEntry) String() string {
    return net.Subnet
}

func (net *SubnetEntry) Hash() string {
    var hash string
    tmp := []string{}
    for _, he := range net.Hosts {
	    tmp = append(tmp, he.String())
	}
	sort.Strings(tmp)
	_calcHash(&hash, tmp)

    return hash
}

type HostEntry struct {
	Name        string
	Source      string
    IP          net.IP
    Datacenter  string
    SaaS        string
    Cloud       string
    AD          string
    Hostnames   []string
    Ports       []*PortEntry
    Hide        bool
}

func (host *HostEntry) String() string {
    if host.Name != "" && host.Name != host.IP.String()  {
    	return fmt.Sprintf("%s <%s>", host.Name, host.IP.String())
    }else{
    	return host.IP.String()
    }
}

func (host *HostEntry) Hash() string {
    var hash string
    tmp := []string{}
    for _, pe := range host.Ports {
	    tmp = append(tmp, pe.String())
	}
	sort.Strings(tmp)
	_calcHash(&hash, host.Name, host.IP.String(), host.Hostnames, tmp)

    return hash
}

func (host *HostEntry) ChildrenHash() string {
    var hash string
    tmp := []string{}
    for _, pe := range host.Ports {
	    tmp = append(tmp, pe.String())
	}
	sort.Strings(tmp)
	_calcHash(&hash, host.Hostnames, tmp)

    return hash
}

func (host *HostEntry) Uint32Ip() uint32 {
	return tools.IpToUint32(host.IP)
}

type PortEntry struct {
    Port  uint
    Certs []Cert
}

func (port *PortEntry) String() string {
   	return fmt.Sprintf("%d", port.Port)
}

func (port *PortEntry) Hash() string {
    var hash string
    tmp := []string{}
    for _, c := range port.Certs {
	    tmp = append(tmp, c.String())
	}
	sort.Strings(tmp)
	_calcHash(&hash, port.Port, tmp)

    return hash
}

func _calcHash(outValue *string, keyvals ...interface{}) {

	data := ""
	for _, v := range keyvals {
		if _, ok := v.(int); ok {
			data += fmt.Sprintf("%d,", v)
		}else{
			data += fmt.Sprintf("%s,", v)
		}
	}

	h := sha1.New()
	h.Write([]byte(data))

	*outValue = hex.EncodeToString(h.Sum(nil))

}