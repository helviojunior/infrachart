package readers

import (
    "fmt"
    "net"
    "os"
    //"strings"

    "github.com/helviojunior/infrachart/internal/tools"
    "github.com/helviojunior/infrachart/pkg/log"
    "github.com/helviojunior/infrachart/pkg/database"
    resolver "github.com/helviojunior/gopathresolver"

    //enumdns_db "github.com/helviojunior/enumdns/pkg/database"
    //enumdns_models "github.com/helviojunior/enumdns/pkg/models"

    //certcrawler_db "github.com/helviojunior/certcrawler/pkg/database"
    certcrawler_models "github.com/helviojunior/certcrawler/pkg/models"

    netcalc "github.com/helviojunior/pcapraptor/pkg/netcalc"

    "gorm.io/gorm/clause"
)

type Cert struct {
    ID string
    CN string
    AlternateNames string
}

type SubnetEntry struct {
    Subnet string
    Hosts  []*HostEntry
}

type HostEntry struct {
    IP        string
    Hostnames []string
    Ports     []*PortEntry
}

type PortEntry struct {
    Port  uint
    Certs []Cert
}

// Runner is a runner that probes web targets using a driver
type DataReader struct {
    
    //root_node
    rootNode string

    // options for the Runner to consider
    options Options

    //EnumDNS database files
    enumdnsFiles []string

    //EnumDNS database files
    certcrawlerFiles []string

}

func NewDataReader(rootNode string, opts Options) (*DataReader, error) {
    return &DataReader{
        rootNode: rootNode,
        enumdnsFiles: []string{ },
        options: opts,
    }, nil
}

func (r *DataReader) AddDatabase(filePath string) error {
    file, err := resolver.ResolveFullPath(filePath)
    if err != nil {
        return err
    }

    conn, err := database.Connection("sqlite:///"+ file, false, r.options.Logging.DebugDb)
    if err != nil {
        return err
    }

    appName := database.GetDbApplication(conn)

    switch appName {
    case "enumdns":
        r.enumdnsFiles = append(r.enumdnsFiles, filePath)
    case "certcrawler":
        r.certcrawlerFiles = append(r.certcrawlerFiles, filePath)
    case "":
        log.Debug("Invalid database", "file", filePath, "err", "application_info table does not exists or is empty")
    default:
        log.Debug("Invalid database", "file", filePath, "application", appName, "err", "Unknown application")
    }

    return nil
}

func (r *DataReader) GenerateDotFile(dotFilePath string) {
    //
    certificates := r.GetCertificates()

    for _, c := range certificates {
        log.Debug("Cert 2", "c", c)
    }

    subnetList := []netcalc.SubnetData{}
    hostList := []*HostEntry{}

    for _, c := range r.certcrawlerFiles {
        conn, err := database.Connection(fmt.Sprintf("sqlite:///%s", c), true, false)
        if err == nil {
            defer database.CloseDB(conn)

            rHosts, err := conn.Model(&certcrawler_models.Host{}).Preload(clause.Associations).Rows()
            if err == nil {
                defer rHosts.Close()
                var host certcrawler_models.Host
                for rHosts.Next() {
                    var hostEntry *HostEntry
                    var portEntry *PortEntry

                    conn.ScanRows(rHosts, &host)

                    netcalc.AddSlice(&subnetList, netcalc.NewSubnetFromIPMask(net.ParseIP(host.Ip), 32))
        
                    for _, he := range hostList {
                        if hostEntry == nil && he.IP == host.Ip {
                            hostEntry = he
                            for _, pe := range hostEntry.Ports {
                                if portEntry == nil && pe.Port == host.Port {
                                    portEntry = pe
                                }
                            }
                        }
                    }
                    if portEntry == nil {
                        portEntry = &PortEntry{
                            Port     : host.Port,
                            Certs    : []Cert{},
                        }
                    }
                    if hostEntry == nil {

                        hostEntry = &HostEntry{
                            IP      : host.Ip,
                            Ports   : []*PortEntry{ portEntry, },
                        }
                        hostList = append(hostList, hostEntry)
                    }

                    // Update certs
                    for _, cert := range host.Certificates {
                        for _, ec := range certificates {
                            if ec.ID == cert.Hash {
                                find := false
                                for _, pec := range portEntry.Certs {
                                    if pec.ID == cert.Hash {
                                        find = true
                                    }
                                }
                                if !find {
                                    portEntry.Certs = append(portEntry.Certs, ec)
                                }
                            }
                        }
                    }
                    
                
                }
            }
        }
        
    }

    subnetList2 := []string{}
    for _, subnet := range subnetList {
        n := fmt.Sprintf("%s/%d", subnet.Net, subnet.Mask)
        if !tools.SliceHasStr(subnetList2, n) {
            subnetList2 = append(subnetList2, n)
        }
    }

    log.Warn("Calculating supernets...")
    supnetList2 := []string{}
    netGroups := netcalc.GroupSubnets(subnetList2)
    for i, group := range netGroups {
        supnet := netcalc.CalculateSupernet(group)
        n := supnet.String()
        if !tools.SliceHasStr(supnetList2, n) {
            supnetList2 = append(supnetList2, n)
            log.Infof("Supernet %04d: %s (from %d subnets)", i+1, n, len(group))
        }
    }

    topList := []*SubnetEntry{}
    for _, netIp := range supnetList2 {
        _, subnet, err := net.ParseCIDR(netIp)
        if err != nil {
            log.Debug("Error parsing network ip", "err", err)
        }

        if err == nil {
            subnetEntry := &SubnetEntry{
                Subnet    : netIp,
                Hosts     : []*HostEntry{},
            }

            for _, he := range hostList {
                if subnet.Contains(net.ParseIP(he.IP)) {
                     subnetEntry.Hosts = append(subnetEntry.Hosts, he)      
                }
            }

            topList = append(topList, subnetEntry)
        }

    }

    topList = topList[:7]

    f, _ := os.Create(dotFilePath)
    defer f.Close()

    fmt.Fprintln(f, "strict digraph {")
    fmt.Fprintln(f, "    pad=0;")
    fmt.Fprintf(f, "    size=\"%d!\";", 5*len(topList))
    fmt.Fprintln(f, "    rankdir=TB;")
    fmt.Fprintln(f, "    ranksep=\"1.2 equally\";")
    fmt.Fprintln(f, "    nodesep=\"0.8\";")
    fmt.Fprintln(f, "    overlap=\"prism\";")
    fmt.Fprintln(f, "    node [shape=plaintext style=\"filled,rounded\" penwidth=1.4 fontsize=12];")

    //fmt.Fprintln(f, "    client_name [ style=\"filled\" shape=underline fillcolor=\"#ffffff\" label=\"Sec4US\"]")
    //fmt.Fprintf(f, "    client_name [label=\"%s\" shape=\"polygon\", sides=10, distortion=\"0.298417\", orientation=65, skew=\"0.310367\", color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)
    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"hexagon\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)
    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"tab\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)

    fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"component\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", r.rootNode)


    ipCount := 0
    for i, subnet := range topList {
        subnetName := fmt.Sprintf("subnet_%d", i)

        fmt.Fprintf(f, "    \"%s\" [shape=signature color=\"#445383\" fillcolor=\"#708bce\" label=\"%s\"]\n", subnetName, subnet.Subnet)
        fmt.Fprintf(f, "    client_name -> %s [fillcolor=\"#00000014\" color=\"#00000014\"]\n", subnetName)

        for _, host := range subnet.Hosts {
            ipNode := fmt.Sprintf("ip_%d", ipCount)
            fmt.Fprintf(f, "    %s [ shape=box label=\"%s\" ];\n", ipNode, host.IP)
            fmt.Fprintf(f, "    %s -> \"%s\" [label=\"\" color=\"#999999\"]\n", subnetName, ipNode)
            ipCount++

        }
        
    }

    ipCount = 0
    for _, subnet := range topList {
        for _, host := range subnet.Hosts {
            ipNode := fmt.Sprintf("ip_%d", ipCount)

            for _, hn := range host.Hostnames {
                hnNode := fmt.Sprintf("%s_hn", hn)
                fmt.Fprintf(f, "    \"%s\" [shape=underline fillcolor=\"#ffffff\" label=\"%s\"]\n", hnNode, hn)
                fmt.Fprintf(f, "    %s -> \"%s\" [label=\"hostname\" color=\"#999999\"]\n", ipNode, hnNode)
            }

            for _, port := range host.Ports {
                portNode := fmt.Sprintf("%s_p%d", ipNode, port.Port)
                fmt.Fprintf(f, "    \"%s\" [shape=oval label=\"Port %d\" fillcolor=\"#b2df8a\"]\n", portNode, port.Port)
                fmt.Fprintf(f, "    %s -> \"%s\" [label=\"port\" color=\"#33a02c\"]\n", ipNode, portNode)

                if len(port.Certs) == 0 {
                    noCertNode := fmt.Sprintf("%s_none", portNode)
                    fmt.Fprintf(f, "    \"%s\" [label=\"No Cert\" shape=note style=dashed fillcolor=\"#f2f2f2\"]\n", noCertNode)
                    fmt.Fprintf(f, "    \"%s\" -> \"%s\" [label=\"cert\" color=\"#bbbbbb\"]\n", portNode, noCertNode)
                } else {
                    for _, cert := range port.Certs {
                        certNode := cert.ID
                        fmt.Fprintf(f, "    \"%s\" [label=\"%s\" shape=note fillcolor=\"#cab2d6\"]\n", certNode, cert.CN)
                        fmt.Fprintf(f, "    \"%s\" -> \"%s\" [label=\"cert\" color=\"#6a3d9a\"]\n", portNode, certNode)
                    }
                }
            }

            

            ipCount++
        }
    }

    fmt.Fprintln(f, "}")

}

func (r *DataReader) GetCertificates() []Cert {
    certificates := []Cert{}

    for _, c := range r.certcrawlerFiles {
        conn, err := database.Connection(fmt.Sprintf("sqlite:///%s", c), true, false)
        if err != nil {
            return certificates
        }
        defer database.CloseDB(conn)

        rCerts, err := conn.Model(&certcrawler_models.Certificate{}).Preload(clause.Associations).Where("is_ca = 0 or (is_ca = 1 and self_signed = 0)").Rows()
        if err == nil {
            defer rCerts.Close()
            var cert certcrawler_models.Certificate
            for rCerts.Next() {
                conn.ScanRows(rCerts, &cert)
                find := false
                for _, ec := range certificates {
                    if ec.ID == cert.Hash {
                        find = true
                    }
                }
                if !find {
                    certificates = append(certificates, Cert{
                        ID        : cert.Hash,
                        CN        : tools.FormatCN(cert.Subject),
                    })
                }
            }
        }

        
    }

    return certificates
}


func (r *DataReader) Close() {
    r.enumdnsFiles = []string{ }
}
