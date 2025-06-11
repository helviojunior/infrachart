package readers

import (
    "fmt"
    "net"
    "os"
    "strings"

    "github.com/helviojunior/infrachart/internal/tools"
    "github.com/helviojunior/infrachart/pkg/log"
    "github.com/helviojunior/infrachart/pkg/database"
    resolver "github.com/helviojunior/gopathresolver"

    //enumdns_db "github.com/helviojunior/enumdns/pkg/database"
    //enumdns_models "github.com/helviojunior/enumdns/pkg/models"

    //certcrawler_db "github.com/helviojunior/certcrawler/pkg/database"
    certcrawler_models "github.com/helviojunior/certcrawler/pkg/models"

    netcalc "github.com/helviojunior/pcapraptor/pkg/netcalc"

    "database/sql"
    "gorm.io/gorm/clause"
)

var topTCPPorts = []uint{
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1025, 1433, 1723, 3306, 3389,
    5900, 8080, 8443, 8888, 20, 26, 49, 69, 161, 389,
    636, 873, 989, 990, 992, 993, 995, 1080, 1194, 1434,
    1521, 2049, 2121, 3300, 3388, 4444, 4662, 5000, 5060, 5432,
    5631, 5666, 5800, 5901, 6000, 6001, 6002, 6646, 6666, 6697,
    8000, 8008, 8081, 8181, 8222, 8444, 8880, 8881, 8882, 8883,
    9000, 9090, 9100, 9200, 9300, 9418, 9999, 10000, 10001, 10010,
    10243, 11371, 12000, 12345, 13720, 13721, 14550, 15000, 16080, 18080,
    20000, 24800, 27017, 28017, 31337, 32768, 32769, 49152, 49153, 49154,
    10443, 5443,
}

func IsTopPort(port uint) bool {

    for _, p := range topTCPPorts {
        if p == port {
            return true
        }
    }

    return false
} 

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
    //certificates := r.GetCertificates()

    /*
    for _, c := range certificates {
        log.Debug("Cert 2", "c", c)
    }*/

    subnetList := []netcalc.SubnetData{}
    hostList := []*HostEntry{}

    for _, c := range r.certcrawlerFiles {
        conn, err := database.Connection(fmt.Sprintf("sqlite:///%s", c), true, false)
        if err == nil {
            defer database.CloseDB(conn)

            var rHosts *sql.Rows

            if len(r.options.FilterList) > 0 {
                var ids = []int{}
                sqlHosts := r.prepareSQL([]string{"h.ptr", "cn.name"})

                if err := conn.Raw("SELECT distinct h.id from hosts_certs as hc inner join cert_names as cn on cn.certificate_id = hc.certificate_id inner join hosts as h on h.id = hc.host_id WHERE cn.name != '' " + sqlHosts).Find(&ids).Error; err == nil {
                
                    rHosts, err = conn.Model(&certcrawler_models.Host{}).Preload(clause.Associations).Where("id in ?", ids).Rows()
                }
            }else{
                rHosts, err = conn.Model(&certcrawler_models.Host{}).Preload(clause.Associations).Rows()
            }

            if err == nil {
                defer rHosts.Close()
                var host certcrawler_models.Host
                for rHosts.Next() {
                    var hostEntry *HostEntry
                    var portEntry *PortEntry

                    conn.ScanRows(rHosts, &host)
                    conn.Model(&host).Association("Certificates").Find(&host.Certificates)

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
                    if portEntry == nil && IsTopPort(host.Port) {
                        portEntry = &PortEntry{
                            Port     : host.Port,
                            Certs    : []Cert{},
                        }
                    }
                    if hostEntry == nil && portEntry != nil {

                        hostEntry = &HostEntry{
                            IP      : host.Ip,
                            Ports   : []*PortEntry{ portEntry, },
                        }
                        hostList = append(hostList, hostEntry)
                    }

                    // Update certs
                    if hostEntry != nil && portEntry != nil {
                        for _, cert := range host.Certificates {
                            if !cert.IsCA || (cert.IsCA && cert.SelfSigned) {
                                portEntry.Certs = append(portEntry.Certs, Cert{
                                    ID        : cert.Hash,
                                    CN        : tools.FormatCN(cert.Subject),
                                })
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
            log.Debugf("Supernet %04d: %s (from %d subnets)", i+1, n, len(group))
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

    //topList = topList[:3]

    switch strings.ToLower(r.options.ChartType){
        case "hosts":
            r.GenerateHostPortDotFile(dotFilePath, topList, false)
        case "certificates":
            r.GenerateCertificatesDotFile(dotFilePath, topList)
    }



}

func (r *DataReader) GenerateHostPortDotFile(dotFilePath string, topList []*SubnetEntry, sumarizePorts bool) {

    f, _ := os.Create(dotFilePath)
    defer f.Close()


    hostCount := 0
    for _, subnet := range topList {
        hostCount += len(subnet.Hosts)
    }

    if hostCount < 120 {
        hostCount = 120
    }

    fmt.Fprintln(f, "strict digraph {")
    fmt.Fprintln(f, "    layout=twopi;")
    fmt.Fprintf(f, "    size=\"%d!\";\n", (hostCount/2))
    fmt.Fprintln(f, "    rankdir=TB;")
    fmt.Fprintln(f, "    ratio=auto;")
    fmt.Fprintln(f, "    ranksep=\"3 equally\";")
    fmt.Fprintln(f, "    nodesep=\"0.8\";")
    fmt.Fprintln(f, "    overlap=\"prism\";")
    fmt.Fprintln(f, "    node [shape=plaintext style=\"filled,rounded\" penwidth=1.4 fontsize=12];")

    //fmt.Fprintln(f, "    client_name [ style=\"filled\" shape=underline fillcolor=\"#ffffff\" label=\"Sec4US\"]")
    //fmt.Fprintf(f, "    client_name [label=\"%s\" shape=\"polygon\", sides=10, distortion=\"0.298417\", orientation=65, skew=\"0.310367\", color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)
    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"hexagon\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)
    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"tab\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)

    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"component\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", r.rootNode)

    ipCount := 0
    for i, subnet := range topList {
        subnetName := fmt.Sprintf("subnet_%d", i)

        fmt.Fprintf(f, "    \"%s\" [shape=signature color=\"#445383\" fillcolor=\"#708bce\" label=\"%s\"]\n", subnetName, subnet.Subnet)
        //fmt.Fprintf(f, "    client_name -> %s [fillcolor=\"#00000014\" color=\"#00000014\"]\n", subnetName)

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

            if sumarizePorts {
                strP := []string{}
                for _, port := range host.Ports {
                    strP = append(strP, fmt.Sprintf("%d", port.Port))
                }

                portNode := fmt.Sprintf("%s_p%d", ipNode, "all")

                fmt.Fprintf(f, "    \"%s\" [shape=oval label=\"%s\" fillcolor=\"#b2df8a\"]\n", portNode, strings.Join(strP, ", "))
                fmt.Fprintf(f, "    %s -> \"%s\" [label=\"port\" color=\"#33a02c\"]\n", ipNode, portNode)
            }else{
                for _, port := range host.Ports {
                    portNode := fmt.Sprintf("%s_p%d", ipNode, port.Port)
                    fmt.Fprintf(f, "    \"%s\" [shape=oval label=\"Port %d\" fillcolor=\"#b2df8a\"]\n", portNode, port.Port)
                    fmt.Fprintf(f, "    %s -> \"%s\" [label=\"port\" color=\"#33a02c\"]\n", ipNode, portNode)

                    
                    if len(port.Certs) == 0 {
                        noCertNode := fmt.Sprintf("%s_none", portNode)
                        fmt.Fprintf(f, "    \"%s\" [label=\"No Cert\" shape=note style=dashed fillcolor=\"#f2f2f2\"]\n", noCertNode)
                        fmt.Fprintf(f, "    \"%s\" -> \"%s\" [label=\"cert\" color=\"#bbbbbb\"]\n", portNode, noCertNode)
                    } else {
                        strCert := []string{}
                        for _, cert := range port.Certs {
                            strCert = append(strCert, cert.CN)
                        }

                        certNode := fmt.Sprintf("%s_certs", portNode) 
                        fmt.Fprintf(f, "    \"%s\" [label=\"%s\" shape=note fillcolor=\"#cab2d6\"]\n", certNode, strings.Join(strCert, "\n"))
                        fmt.Fprintf(f, "    \"%s\" -> \"%s\" [label=\"cert\" color=\"#6a3d9a\"]\n", portNode, certNode)

                        /*for _, cert := range port.Certs {
                            certNode := fmt.Sprintf("%s_cer_%s", portNode, cert.ID) 
                            fmt.Fprintf(f, "    \"%s\" [label=\"%s\" shape=note fillcolor=\"#cab2d6\"]\n", certNode, cert.CN)
                            fmt.Fprintf(f, "    \"%s\" -> \"%s\" [label=\"cert\" color=\"#6a3d9a\"]\n", portNode, certNode)
                        }*/
                    }
                }
            }

            ipCount++
        }
    }

    fmt.Fprintln(f, "}")
}


func (r *DataReader) GenerateCertificatesDotFile(dotFilePath string, topList []*SubnetEntry) {

    f, _ := os.Create(dotFilePath)
    defer f.Close()

    hostCount := 0
    for _, subnet := range topList {
        hostCount += len(subnet.Hosts)
    }

    if hostCount < 120 {
        hostCount = 120
    }

    fmt.Fprintln(f, "strict digraph {")
    fmt.Fprintln(f, "    layout=twopi;")
    fmt.Fprintf(f, "    size=\"%d!\";\n", (hostCount/2))
    fmt.Fprintln(f, "    rankdir=TB;")
    fmt.Fprintln(f, "    ratio=auto;")
    fmt.Fprintln(f, "    ranksep=\"3 equally\";")
    fmt.Fprintln(f, "    nodesep=\"0.8\";")
    fmt.Fprintln(f, "    overlap=\"prism\";")
    fmt.Fprintln(f, "    node [shape=plaintext style=\"filled,rounded\" penwidth=1.4 fontsize=12];")

    //fmt.Fprintln(f, "    client_name [ style=\"filled\" shape=underline fillcolor=\"#ffffff\" label=\"Sec4US\"]")
    //fmt.Fprintf(f, "    client_name [label=\"%s\" shape=\"polygon\", sides=10, distortion=\"0.298417\", orientation=65, skew=\"0.310367\", color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)
    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"hexagon\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)
    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"tab\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)

    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"component\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", r.rootNode)

    
    for _, subnet := range topList {
        for _, host := range subnet.Hosts {
            for _, port := range host.Ports {
                for _, cert := range port.Certs {
                    certNode := cert.ID
                    fmt.Fprintf(f, "    \"%s\" [label=\"%s\" shape=note fillcolor=\"#cab2d6\"]\n", certNode, cert.CN)
                }

            }
        }
    }

    ipCount := 0
    for i, subnet := range topList {
        for _, host := range subnet.Hosts {
            for _, port := range host.Ports {                    
                if len(port.Certs) > 0 {
                    for _, cert := range port.Certs {
                        certNode := cert.ID
                        subnetName := fmt.Sprintf("c_%s_subnet_%d", certNode, i)
                        ipNode := fmt.Sprintf("%s_ip%d", subnetName, ipCount)
                        portNode := fmt.Sprintf("%s_p%d", ipNode, port.Port)

                        fmt.Fprintf(f, "    \"%s\" [shape=signature color=\"#445383\" fillcolor=\"#708bce\" label=\"%s\"]\n", subnetName, subnet.Subnet)
                        fmt.Fprintf(f, "    \"%s\" -> \"%s\" [label=\"\" color=\"#6a3d9a\"]\n", certNode, subnetName)

                        fmt.Fprintf(f, "    %s [ shape=box label=\"%s\" ];\n", ipNode, host.IP)
                        //fmt.Fprintf(f, "    %s -> \"%s\" [label=\"\" color=\"#999999\"]\n", subnetName, ipNode)
                        

                        portNode = fmt.Sprintf("%s_p%d", subnetName, port.Port)
                        fmt.Fprintf(f, "    \"%s\" [shape=oval label=\"Port %d\" fillcolor=\"#b2df8a\"]\n", portNode, port.Port)
                        //fmt.Fprintf(f, "    %s -> \"%s\" [label=\"port\" color=\"#33a02c\"]\n", ipNode, portNode)
                        fmt.Fprintf(f, "    %s -> \"%s\" [label=\"\" color=\"#33a02c\"]\n", subnetName, portNode)
                        fmt.Fprintf(f, "    %s -> \"%s\" [label=\"\" color=\"#999999\"]\n", portNode, ipNode)

                        ipCount++

                    }

                }

            }
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


func (r *DataReader) prepareSQL(fields []string) string {
    sql := ""
    for _, f := range fields {
        for _, w := range r.options.FilterList {
            if sql != "" {
                sql += " or "
            }
            sql += " " + f + " like '%"+ w + "%' "
        }
    }
    if sql != "" {
        sql = " and (" + sql + ")"
    }
    return sql
}

func (r *DataReader) Close() {
    r.enumdnsFiles = []string{ }
}
