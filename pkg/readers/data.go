package readers

import (
    "fmt"
    "net"
    "os"
    "strings"
    "path/filepath"
    "encoding/json"
    "sort"

    "github.com/helviojunior/infrachart/internal/tools"
    "github.com/helviojunior/infrachart/pkg/log"
    "github.com/helviojunior/infrachart/pkg/database"
    "github.com/helviojunior/infrachart/pkg/models"
    resolver "github.com/helviojunior/gopathresolver"
    enumdns_run "github.com/helviojunior/enumdns/pkg/runner"
    enumdns_models "github.com/helviojunior/enumdns/pkg/models"
    certcrawler_models "github.com/helviojunior/certcrawler/pkg/models"
    netcalc "github.com/helviojunior/pcapraptor/pkg/netcalc"

    "github.com/lair-framework/go-nmap"
    "database/sql"
    "gorm.io/gorm/clause"
)

// Runner is a runner that probes web targets using a driver
type DataReader struct {

    // options for the Runner to consider
    options Options

    //EnumDNS database files
    enumdnsFiles []string

    //Cert Crawler database files
    certcrawlerFiles []string

    //NMAP database files
    nmapFiles []string
}

func NewDataReader(opts Options) (*DataReader, error) {
    return &DataReader{
        enumdnsFiles: []string{ },
        options: opts,
    }, nil
}

func (r *DataReader) AddDatabase(filePath string) error {
    file, err := resolver.ResolveFullPath(filePath)
    if err != nil {
        return err
    }

    if strings.ToLower(filepath.Ext(filePath)) == ".xml" {
        _, err := r.getNmapXML(filePath)
        if err != nil {
            return err
        }

        //OK is an valid NMAP XML
        r.nmapFiles = append(r.nmapFiles, filePath)

    }else{

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
    }

    return nil
}

func (r *DataReader) GenerateDotFile(dotFilePath string) error {
    //
    //certificates := r.GetCertificates()

    /*
    for _, c := range certificates {
        log.Debug("Cert 2", "c", c)
    }*/

    subnetList := []netcalc.SubnetData{}
    saasSubnetList := []netcalc.SubnetData{}
    hostList := []*models.HostEntry{}

    for _, eDNS := range r.enumdnsFiles {
        log.Info("Reading EnumDNS file", "file", eDNS)
        regCount := 0
        conn, err := database.Connection(fmt.Sprintf("sqlite:///%s", eDNS), true, false)
        if err != nil {
            return err
        }
        defer database.CloseDB(conn)

        var rResults *sql.Rows

        if len(r.options.FilterList) > 0 {
            sqlHosts := r.prepareSQL([]string{"fqdn", "ptr"})

            rResults, err = conn.Model(&enumdns_models.Result{}).Preload(clause.Associations).Where("[exists] = 1 AND (ipv4 != '' or ipv6 != '') " + sqlHosts).Rows()
            
        }else{
            rResults, err = conn.Model(&enumdns_models.Result{}).Preload(clause.Associations).Rows()
        }
        if err != nil {
            return err
        }

        defer rResults.Close()
        var resultItem enumdns_models.Result
        for rResults.Next() {
            var hostEntry *models.HostEntry

            conn.ScanRows(rResults, &resultItem)

            for _, he := range hostList {
                if hostEntry == nil && he.IP.String() == resultItem.IPv4 {
                    hostEntry = he
                }
            }
            
            if hostEntry == nil {

                hostEntry = &models.HostEntry{
                    Name      : resultItem.IPv4,
                    IP        : net.ParseIP(resultItem.IPv4),
                    Ports     : []*models.PortEntry{ },
                    Hostnames : []string{},
                    Hide      : (!r.options.FullChart && resultItem.SaaSProduct != ""),
                }

                if r.options.Logging.Debug {
                    hostEntry.Source = "EnumDNS"
                }

                if resultItem.DC {
                    hostEntry.AD = "Domain Controller"
                }

                hostList = append(hostList, hostEntry)
            }

            if hostEntry != nil {

                regCount++
                ptr := strings.Trim(resultItem.Ptr, ".")
                hostName := strings.Trim(resultItem.FQDN, ".")

                r.CheckProductsInfo(hostEntry, ptr, hostName)

                if ptr != "" {
                    //No filter out PTR data   
                    hostEntry.AddHostname(ptr)

                    r.AddSaaS(net.ParseIP(resultItem.IPv4), ptr, &saasSubnetList)
                }

                if hostName != "" {
                    if len(r.options.FilterList) > 0 {
                        for _, f := range r.options.FilterList {
                            if strings.Contains(hostName, f) {
                                hostEntry.AddHostname(hostName)
                            }
                        }
                    }else {
                        hostEntry.AddHostname(hostName)
                    }
                }

            }
        }
    
        log.Infof("Processed %d hosts", regCount)
        
    }

    for _, nmap := range r.nmapFiles {
        log.Info("Reading NMAP file", "file", nmap)
        regCount := 0
        nmapXML, err := r.getNmapXML(nmap)
        if err == nil {
            for _, host := range nmapXML.Hosts {
                var hostEntry *models.HostEntry
                var portEntry *models.PortEntry

                ptr := ""
                for _, hostName := range host.Hostnames {
                    if strings.ToLower(hostName.Type) == "ptr" && hostName.Name != "" {
                        ptr = strings.Trim(strings.ToLower(hostName.Name), " ")
                    }
                }

                for _, address := range host.Addresses {
                    if !tools.SliceHasStr([]string{"ipv4", "ipv6"}, address.AddrType) {
                        continue
                    }

                    ip := net.ParseIP(address.Addr)
                    if ip == nil {
                        log.Debugf("Invalid IP (%s)", address.Addr)
                        continue
                    }

                    for _, he := range hostList {
                        if hostEntry == nil && he.IP.String() == address.Addr {
                            hostEntry = he
                        }
                    }
                    
                    if hostEntry == nil {

                        hostEntry = &models.HostEntry{
                            Name      : address.Addr,
                            IP        : ip,
                            Ports     : []*models.PortEntry{ },
                            Hostnames : []string{},
                            Hide      : false,
                        }

                        if r.options.Logging.Debug {
                            hostEntry.Source = "NMAP"
                        }

                    }

                    if hostEntry != nil {

                        regCount++

                        if ptr != "" {
                            //No filter out PTR data   
                            if !tools.SliceHasStr(hostEntry.Hostnames, ptr) {
                                hostEntry.Hostnames = append(hostEntry.Hostnames, ptr)
                            }

                            if !r.options.FullChart && r.AddSaaS(ip, ptr, &saasSubnetList) {
                                hostEntry.Hide = true
                            }
                        }

                        pCount := 0
                        for _, port := range host.Ports {
                            // filter only open ports
                            if port.State.State != "open" {
                                continue
                            }

                            portEntry = &models.PortEntry{
                                Port     : uint(port.PortId),
                                Certs    : []models.Cert{},
                            }

                            if port.Service.Name == "kerberos-sec" && hostEntry.AD == ""{
                                hostEntry.AD = "Domain Controller"
                            }

                            // Check certificates
                            for _, script := range port.Scripts {
                                if script.Id == "ssl-cert" {
                                    certPem := ""
                                    isCA := false
                                    newCrt := models.Cert{
                                        ID        : "",
                                        CN        : "", 
                                        AlternateNames : []string{},
                                    }
                                    for _, element := range script.Elements {
                                        k := strings.ToLower(element.Key)
                                        v := element.Value

                                        switch k{
                                        case "pem":
                                            certPem = v
                                        }
                                    }

                                    for _, table := range script.Tables {
                                        for _, element := range table.Elements {
                                            k := strings.ToLower(element.Key)
                                            v := element.Value

                                            switch k{
                                            case "commonname":
                                                newCrt.CN = tools.FormatCN(v)
                                            case "sha1":
                                                newCrt.ID = strings.ToLower(v)
                                            case "sha256":
                                                newCrt.ID = strings.ToLower(v)
                                            case "x509v3 subject alternative name":
                                                //certPem = strings.ToLower(v)
                                            case "x509v3 basic constraints":
                                                if strings.Contains(v, "CA:true") {
                                                    isCA = true
                                                }
                                            }
                                        }
                                    }

                                    alternateNames := []string{}
                                    if certPem != "" {
                                        crt, err := tools.ParseCertificatePEM(certPem)
                                        if err == nil {

                                            newCrt.SelfSigned = tools.IsSelfSigned(crt)
                                            isCA = crt.IsCA

                                            newCrt.CN = tools.FormatCN(crt.Subject.String())
                                            newCrt.ID = tools.GetHash(crt.Signature)

                                            if len(crt.DNSNames) > 0 {
                                                for _, n := range crt.DNSNames {
                                                    alternateNames = append(alternateNames, tools.FormatCN(n))
                                                }
                                            }
                                            if len(crt.IPAddresses) > 0 {
                                                for _, n := range crt.IPAddresses {
                                                    alternateNames = append(alternateNames, n.String())
                                                }

                                            }
                                            if len(crt.EmailAddresses) > 0 {
                                                for _, n := range crt.EmailAddresses {
                                                    alternateNames = append(alternateNames, tools.FormatCN(n))
                                                }
                                            }
                                            if len(crt.URIs) > 0 {
                                                for _, n := range crt.URIs {
                                                    alternateNames = append(alternateNames, tools.FormatCN(n.String()))
                                                }
                                            }

                                        }
                                    }
                                    for _, alt := range alternateNames {
                                        if len(r.options.FilterList) > 0 {
                                            for _, f := range r.options.FilterList {
                                                if strings.Contains(alt, f) && alt != newCrt.CN {
                                                    newCrt.AddAlternateNames(alt)
                                                }
                                            }
                                        }else{
                                            if alt != newCrt.CN {
                                                newCrt.AddAlternateNames(alt)
                                            }
                                        }
                                    }
                                    if newCrt.ID != "" && newCrt.CN != "" {
                                        add := false
                                        if len(r.options.FilterList) > 0 {
                                            for _, f := range r.options.FilterList {
                                                if strings.Contains(newCrt.CN, f) {
                                                    add = true
                                                }
                                            }
                                            if !add && len(newCrt.AlternateNames) > 0 {
                                                add = true
                                            }
                                        }else {
                                            add = true
                                        }

                                        if add && (!isCA || newCrt.SelfSigned) {
                                            portEntry.Certs = append(portEntry.Certs, newCrt)
                                        }
                                    }
                                    
                                }
                            }

                            hostEntry.Ports = append(hostEntry.Ports, portEntry)
                            pCount++
                        }

                        if pCount > 0 {
                            add := false
                            if len(r.options.FilterList) > 0 {
                                hostList = append(hostList, hostEntry)

                                // serialize to Json and check strings
                                j, err := json.Marshal(host)
                                if err != nil {
                                    return err
                                }
                                jsonStr := string(j)

                                for _, f := range r.options.FilterList {
                                    if strings.Contains(jsonStr, f) {
                                        add = true
                                    }
                                }

                            }else{
                                add = true
                            }
                            if add {
                                r.CheckProductsInfo(hostEntry, host.Hostnames)
                                hostList = append(hostList, hostEntry)
                            }
                        }
                    }

                }
            }
        }
        log.Infof("Processed %d hosts", regCount)
    }

    for _, c := range r.certcrawlerFiles {
        log.Info("Reading CertCrawler file", "file", c)
        regCount := 0
        conn, err := database.Connection(fmt.Sprintf("sqlite:///%s", c), true, false)
        if err != nil {
            return err
        }

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

        if err != nil {
            return err
        }

        defer rHosts.Close()
        var host certcrawler_models.Host
        for rHosts.Next() {
            var hostEntry *models.HostEntry
            var portEntry *models.PortEntry

            conn.ScanRows(rHosts, &host)
            conn.Model(&host).Association("Certificates").Find(&host.Certificates)

            for _, he := range hostList {
                if hostEntry == nil && he.IP.String() == host.Ip {
                    hostEntry = he
                    for _, pe := range hostEntry.Ports {
                        if portEntry == nil && pe.Port == host.Port {
                            portEntry = pe
                        }
                    }
                }
            }
            if portEntry == nil {
                portEntry = &models.PortEntry{
                    Port     : host.Port,
                    Certs    : []models.Cert{},
                }
            }

            if hostEntry == nil && portEntry != nil {

                hostEntry = &models.HostEntry{
                    Name      : host.Ip,
                    IP        : net.ParseIP(host.Ip),
                    Ports     : []*models.PortEntry{ portEntry, },
                    Hostnames : []string{},
                    Hide      : false,
                }

                if r.options.Logging.Debug {
                    hostEntry.Source = "CertCrawler" 
                }

            }

            if hostEntry != nil && portEntry != nil {

                regCount++

                if host.Ptr != "" {

                    r.CheckProductsInfo(hostEntry, host.Ptr)

                    //No filter out PTR data   
                    hostEntry.AddHostname(host.Ptr)
                
                    r.AddSaaS(net.ParseIP(host.Ip), host.Ptr, &saasSubnetList)
                }

                for _, cert := range host.Certificates {
                    if !cert.IsCA || (cert.SelfSigned && len(host.Certificates) == 1) {
                        ins := false
                        r.CheckProductsInfo(hostEntry, cert.Subject, cert.Names)
                        if len(r.options.FilterList) > 0 {
                            for _, f := range r.options.FilterList {
                                if strings.Contains(cert.Subject, f) {
                                    ins = true
                                }else {
                                    for _, alt := range cert.Names {
                                        if strings.Contains(alt.Name, f) {
                                            ins = true
                                        }
                                    }
                                }
                            }
                        }else{
                            ins = true
                        }
                        if ins {
                            newCrt := models.Cert{
                                ID        : cert.Hash,
                                CN        : tools.FormatCN(cert.Subject),
                                SelfSigned: cert.SelfSigned,
                                AlternateNames : []string{},
                            }
                            
                            for _, alt := range cert.Names {
                                if len(r.options.FilterList) > 0 {
                                    for _, f := range r.options.FilterList {
                                        if strings.Contains(alt.Name, f) && alt.Name != newCrt.CN {
                                            newCrt.AddAlternateNames(alt.Name)
                                        }
                                    }
                                }else{
                                    if alt.Name != newCrt.CN {
                                        newCrt.AddAlternateNames(alt.Name)
                                    }
                                }
                            }
                            portEntry.Certs = append(portEntry.Certs, newCrt)
                        }
                    }

                }

                hostList = append(hostList, hostEntry)
            }


        }
    
    
        log.Infof("Processed %d hosts", regCount)
    }


    log.Debug("Hosts", "count", len(hostList))

    //Sort Slice using IP
    sort.Slice(hostList, func(i, j int) bool {
        return hostList[i].Uint32Ip() < hostList[j].Uint32Ip()
    })

    // Add all host IPs to list
    for _, host := range hostList {
        add := false
        if len(r.options.SubnetFilterList) > 0 {
            for _, f := range r.options.SubnetFilterList {
                if f.Contains(host.IP) {
                    add = true
                }
            }
        }else{
            add = true
        }
        if add {
            netcalc.AddSlice(&subnetList, netcalc.NewSubnetFromIPMask(host.IP, 32))
        }
    }

    saasSubnetList2 := []net.IPNet{}
    for _, saasSubnet := range saasSubnetList {
        n := fmt.Sprintf("%s/%d", saasSubnet.Net, saasSubnet.Mask)
        _, subnet, err := net.ParseCIDR(n)
        if err != nil {
            log.Debug("Error parsing network ip", "err", err)
        }
        saasSubnetList2 = append(saasSubnetList2, *subnet)
    }

    subnetList2 := []string{}
    for _, subnet := range subnetList {
        n := fmt.Sprintf("%s/%d", subnet.Net, subnet.Mask)
        if !tools.SliceHasStr(subnetList2, n) {
            subnetList2 = append(subnetList2, n)
        }
    }

    log.Info("Calculating supernets...")
    supnetList2 := []string{}
    netGroups := netcalc.GroupSubnets(subnetList2)
    for i, group := range netGroups {
        supnet := netcalc.CalculateSupernet(group)
        n := supnet.String()
        if !tools.SliceHasStr(supnetList2, n) {
            supnetList2 = append(supnetList2, n)
            log.Debugf("Supernet %04d: %s (from %d ips)", i+1, n, len(group))
        }
    }


    hasIgnored := false
    topList := []*models.SubnetEntry{}
    for _, netIp := range supnetList2 {
        _, subnet, err := net.ParseCIDR(netIp)
        if err != nil {
            log.Debug("Error parsing network ip", "err", err)
        }

        if err == nil {
            subnetEntry := &models.SubnetEntry{
                Subnet    : netIp,
                Hosts     : []*models.HostEntry{},
            }

            var firstWindowsNode *models.HostEntry
            lastName := ""
            for _, he := range hostList {
                if !subnet.Contains(he.IP) {
                    continue
                }

                isValid, isSaas := r.CheckHostEntry(he, saasSubnetList2)

                if isSaas {
                    //log.Debug("Host ignored: identified as SaaS address.", "ip", he.IP)
                }

                log.Debug("Host", "ip", he.IP, "is_valid", isValid, "ports", len(he.Ports))
                if isValid {
                    if firstWindowsNode == nil {
                        firstWindowsNode = he
                        lastName = he.Name
                    }else{
                        if firstWindowsNode.ChildrenHash() != he.ChildrenHash() {

                            if firstWindowsNode.Name != lastName {
                                firstWindowsNode.Name += " - " + lastName
                            }
                            subnetEntry.Hosts = append(subnetEntry.Hosts, firstWindowsNode)
                            firstWindowsNode = he
                            lastName = he.Name
                        }else{
                            lastName = he.Name
                        }
                    }
                }
            
            }
            if firstWindowsNode != nil {
                if firstWindowsNode.Name != lastName {
                    firstWindowsNode.Name += " - " + lastName
                }
                subnetEntry.Hosts = append(subnetEntry.Hosts, firstWindowsNode)
            }

            topList = append(topList, subnetEntry)
        }

    }

    hostCount := 0
    for _, subnet := range topList {
        for _, host := range subnet.Hosts {
            if host.Hide || (len(host.Ports) == 0 && !r.options.FullChart) {
                continue
            }
            hostCount++
        }
    }

    if hostCount == 0 {
        return models.NoDataError{Message:"No items available to write to the chart."}
    }

    if hasIgnored{
        log.Warn("Some SaaS service addresses were ignored. Use the \033[33m-F\033[0m flag to include them.")
    }

    log.Infof("Generating %d host nodes", hostCount)

    //topList = topList[:3]

    switch strings.ToLower(r.options.ChartType){
        case "hosts":
            r.GenerateHostPortDotFile(dotFilePath, topList)
        case "certificates":
            r.GenerateCertificatesDotFile(dotFilePath, topList)
    }

    return nil

}

func (r *DataReader) AddSaaS(ip net.IP, name string, saasSubnetList *[]netcalc.SubnetData) bool{

    if r.options.FullChart {
        return false
    }

    ss, _, _ := enumdns_run.ContainsSaaS(name)
    if ss {
       netcalc.AddSlice(saasSubnetList, netcalc.NewSubnetFromIPMask(ip, 24))
       return true
    }

    return false
}

func (r *DataReader) CheckProductsInfo(host *models.HostEntry, keyvals ...interface{}) { 
    for _, v := range keyvals {
        if dt, ok := v.(string); ok {
            if host.SaaS == "" {
                ss, prodName, _ := enumdns_run.ContainsSaaS(dt)
                if ss {
                   host.SaaS = prodName
                }
            }
            if host.Cloud == "" {
                ss, prodName, _ := enumdns_run.ContainsCloudProduct(dt)
                if ss {
                   host.Cloud = prodName
                }
            }
            if host.Datacenter == "" {
                ss, prodName, _ := enumdns_run.ContainsDatacenter(dt)
                if ss {
                   host.Datacenter = prodName
                }
            }
        }else if dtList, ok := v.([]string); ok {
            for _, dt := range dtList {
                if host.SaaS == "" {
                    ss, prodName, _ := enumdns_run.ContainsSaaS(dt)
                    if ss {
                       host.SaaS = prodName
                    }
                }
                if host.Cloud == "" {
                    ss, prodName, _ := enumdns_run.ContainsCloudProduct(dt)
                    if ss {
                       host.Cloud = prodName
                    }
                }
                if host.Datacenter == "" {
                    ss, prodName, _ := enumdns_run.ContainsDatacenter(dt)
                    if ss {
                       host.Datacenter = prodName
                    }
                }
            }
        }
    }
}

func (r *DataReader) CheckHostEntry(host *models.HostEntry, sassSubnets []net.IPNet) (bool, bool) { // return is_valid and is_sass
    if len(host.Ports) == 0 && !r.options.FullChart {
        return false, false
    }

    // Filter out port list
    tmpList := []*models.PortEntry{}

    if len(host.Ports) > 0 {
        for _, pt := range host.Ports {
            if (len(r.options.Ports) == 0 || tools.SliceHasUInt(r.options.Ports, pt.Port)) {
                if !r.options.CertOnly || (r.options.CertOnly && len(pt.Certs) > 0) {
                    tmpList = append(tmpList, pt)
                }
            }
        }
        if len(tmpList) == 0 {
            if len(host.Ports) > 0 { 
                log.Debug("Host ignored: Open port(s) filtered out by port filter.", "ip", host.IP)
            }
            return false, false
        }
        if !r.options.ShowPorts {
            host.Ports = tmpList
        }
    }

    hasSaas := false
    if !r.options.FullChart {
        for _, saasSubnet := range sassSubnets {
            if saasSubnet.Contains(host.IP) {
                hasSaas = true
            }
        }
    }

    if !hasSaas && len(r.options.FilterList) > 0 {
        isValid := false
        // serialize to Json and check strings
        j, err := json.Marshal(host)
        if err != nil {
            return true, false
        }
        jsonStr := string(j)

        for _, f := range r.options.FilterList {
            if strings.Contains(jsonStr, f) {
                isValid = true
            }
        }
        return isValid, false
    }

    return !hasSaas, hasSaas
}

func (r *DataReader) CalcSize(topList []*models.SubnetEntry) int {

    size := 29
    nodesCount := 0
    for _, subnet := range topList {
        for _, host := range subnet.Hosts {
            if host.Hide {
                continue
            }
            if r.options.Summarize {
                nodesCount += 1 + 2
            }else {
                nodesCount += 1 + len(host.Ports)
            }
            if len(host.Hostnames) > 0 {
                hnCount := len(host.Hostnames)/4
                if hnCount < 1 {
                    hnCount = 1
                }
                nodesCount += hnCount
            }
        }
    }

    size = int(float32(nodesCount) * 0.25)

    if size < 65 {
        if nodesCount < 50 {
            size = 29
        }else{
            size = 65
        }
    }
    if size > 128 {
        size = 128
    }

    log.Debugf("Calculated size to %d nodes: %d inches", nodesCount, size)

    return size
}

func (r *DataReader) GenerateHostPortDotFile(dotFilePath string, topList []*models.SubnetEntry) {

    f, _ := os.Create(dotFilePath)
    defer f.Close()

    size := r.CalcSize(topList)

    fmt.Fprintln(f, "strict digraph {")
    fmt.Fprintln(f, "    layout=twopi;")
    fmt.Fprintf(f, "    size=\"%d!\";\n", size)
    fmt.Fprintln(f, "    rankdir=TB;")
    fmt.Fprintln(f, "    ratio=auto;")
    fmt.Fprintln(f, "    ranksep=\"3 equally\";")
    fmt.Fprintln(f, "    nodesep=\"0.8\";")
    fmt.Fprintln(f, "    overlap=\"prism\";")
    fmt.Fprintln(f, "    dpi=120;")
    fmt.Fprintln(f, "    node [shape=plaintext style=\"filled,rounded\" penwidth=1.4 fontsize=12];")

    //fmt.Fprintln(f, "    client_name [ style=\"filled\" shape=underline fillcolor=\"#ffffff\" label=\"Sec4US\"]")
    //fmt.Fprintf(f, "    client_name [label=\"%s\" shape=\"polygon\", sides=10, distortion=\"0.298417\", orientation=65, skew=\"0.310367\", color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)
    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"hexagon\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)
    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"tab\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)

    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"component\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", r.rootNode)

    ipCount := 0
    for i, subnet := range topList {
        if len(subnet.Hosts) == 0 {
            continue
        }

        subnetName := fmt.Sprintf("subnet_%d", i)

        if !r.options.NoSubnet {
            fmt.Fprintf(f, "    \"%s\" [shape=signature color=\"#445383\" fillcolor=\"#8ba0dc\" label=\"%s\"]\n", subnetName, subnet.Subnet)
            //fmt.Fprintf(f, "    client_name -> %s [fillcolor=\"#00000014\" color=\"#00000014\"]\n", subnetName)
        }

        dcName := ""
        for _, host := range subnet.Hosts {
            if host.Hide || (len(host.Ports) == 0 && !r.options.FullChart) {
                continue
            }

            if dcName == "" && host.Datacenter != "" {
                dcName = host.Datacenter
            }

            nName := host.Name
            if host.Source != "" {
                nName = host.Source + "\n" + host.Name
            }
            ipNode := fmt.Sprintf("ip_%d", ipCount)
            fmt.Fprintf(f, "    %s [ shape=box label=\"%s\" ];\n", ipNode, nName)
            if !r.options.NoSubnet {
                fmt.Fprintf(f, "    %s -> \"%s\" [label=\"\" color=\"#999999\" weight=100]\n", subnetName, ipNode)
            }
            ipCount++
        
        }

        if dcName != "" {
            dcNode := fmt.Sprintf("%s_dc", subnetName)

            fmt.Fprintf(f, "    \"%s\" [shape=box3d fillcolor=\"#d8adad\" color=\"#7d3e3f\" label=\"%s\"]\n", dcNode, dcName)
            fmt.Fprintf(f, "    %s -> \"%s\" [label=\"datacenter\" color=\"#d8adad\" weight=90]\n", dcNode, subnetName)
        }
        
    }

    ipCount = 0
    for _, subnet := range topList {
        for _, host := range subnet.Hosts {
            if host.Hide || (len(host.Ports) == 0 && !r.options.FullChart) {
                continue
            }

            ipNode := fmt.Sprintf("ip_%d", ipCount)

            if len(host.Hostnames) > 0 {
                hnNode := fmt.Sprintf("%s_hn", ipNode)
                strNames := []string{}
                for _, hn := range host.Hostnames {
                    strNames = append(strNames, hn)
                }
                fmt.Fprintf(f, "    \"%s\" [shape=folder fillcolor=\"#71bbc1\" label=\"%s\"]\n", hnNode, strings.Join(strNames, "\n"))
                fmt.Fprintf(f, "    %s -> \"%s\" [label=\"\" color=\"#71bbc1\" weight=90]\n", hnNode, ipNode)
            }

            if host.AD != "" {
                adNode := fmt.Sprintf("%s_ad", ipNode)

                fmt.Fprintf(f, "    \"%s\" [shape=box3d fillcolor=\"#d8adad\" color=\"#7d3e3f\" label=\"%s\"]\n", adNode, host.AD)
                fmt.Fprintf(f, "    %s -> \"%s\" [label=\"\" color=\"#71bbc1\" weight=90]\n", adNode, ipNode)
            }

            if r.options.Summarize {
                strP := []string{}
                strCert := []string{}
                for _, port := range host.Ports {
                    strP = append(strP, fmt.Sprintf("%d", port.Port))

                    for _, cert := range port.Certs {
                        
                        if !tools.SliceHasStr(strCert, cert.CN) {
                            strCert = append(strCert, cert.CN)
                        }
                        for _, alt := range cert.AlternateNames {
                            if !tools.SliceHasStr(strCert, alt) {
                                strCert = append(strCert, alt)
                            }
                        }
                    }

                }

                portNode := fmt.Sprintf("%s_p%d", ipNode, "all")

                if len(strP) > 0 {
                    fmt.Fprintf(f, "    \"%s\" [shape=oval label=\"%s\" fillcolor=\"#b2df8a\"]\n", portNode, strings.Join(strP, ", "))
                    fmt.Fprintf(f, "    %s -> \"%s\" [label=\"\" color=\"#33a02c\" weight=20]\n", ipNode, portNode)
                }

                if len(strCert) > 0 {
                    certNode := fmt.Sprintf("%s_certs", portNode) 
                    fmt.Fprintf(f, "    \"%s\" [label=\"%s\" shape=note fillcolor=\"#cab2d6\"]\n", certNode, strings.Join(strCert, "\n"))
                    fmt.Fprintf(f, "    \"%s\" -> \"%s\" [label=\"cert\" color=\"#6a3d9a\" weight=30]\n", ipNode, certNode)
                }

            }else{
                for _, port := range host.Ports {
                    portNode := fmt.Sprintf("%s_p%d", ipNode, port.Port)
                    fmt.Fprintf(f, "    \"%s\" [shape=oval label=\"Port %d\" fillcolor=\"#b2df8a\"]\n", portNode, port.Port)
                    fmt.Fprintf(f, "    %s -> \"%s\" [label=\"\" color=\"#33a02c\" weight=20]\n", ipNode, portNode)

                    if len(port.Certs) == 0 {
                        //noCertNode := fmt.Sprintf("%s_none", portNode)
                        //fmt.Fprintf(f, "    \"%s\" [label=\"No Cert\" shape=note style=dashed fillcolor=\"#f2f2f2\"]\n", noCertNode)
                        //fmt.Fprintf(f, "    \"%s\" -> \"%s\" [label=\"cert\" color=\"#bbbbbb\"]\n", portNode, noCertNode)
                    } else {
                        strCert := []string{}
                        for _, cert := range port.Certs {
                            n := cert.CN
                            if cert.SelfSigned {
                                n += " (Self Signed)"
                            }
                            if !tools.SliceHasStr(strCert, n) {
                                strCert = append(strCert, n)
                            }
                            for _, alt := range cert.AlternateNames {
                                if !tools.SliceHasStr(strCert, alt) {
                                    strCert = append(strCert, alt)
                                }
                            }
                        }

                        certNode := fmt.Sprintf("%s_certs", portNode) 
                        fmt.Fprintf(f, "    \"%s\" [label=\"%s\" shape=note fillcolor=\"#cab2d6\"]\n", certNode, strings.Join(strCert, "\n"))
                        fmt.Fprintf(f, "    \"%s\" -> \"%s\" [label=\"cert\" color=\"#6a3d9a\" weight=30]\n", portNode, certNode)

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


func (r *DataReader) GenerateCertificatesDotFile(dotFilePath string, topList []*models.SubnetEntry) {

    f, _ := os.Create(dotFilePath)
    defer f.Close()

    size := r.CalcSize(topList)

    fmt.Fprintln(f, "strict digraph {")
    fmt.Fprintln(f, "    layout=twopi;")
    fmt.Fprintf(f, "    size=\"%d!\";\n", size)
    fmt.Fprintln(f, "    rankdir=TB;")
    fmt.Fprintln(f, "    ratio=auto;")
    fmt.Fprintln(f, "    ranksep=\"3 equally\";")
    fmt.Fprintln(f, "    nodesep=\"0.8\";")
    fmt.Fprintln(f, "    overlap=\"prism\";")
    fmt.Fprintln(f, "    dpi=120;")
    fmt.Fprintln(f, "    node [shape=plaintext style=\"filled,rounded\" penwidth=1.4 fontsize=12];")

    //fmt.Fprintln(f, "    client_name [ style=\"filled\" shape=underline fillcolor=\"#ffffff\" label=\"Sec4US\"]")
    //fmt.Fprintf(f, "    client_name [label=\"%s\" shape=\"polygon\", sides=10, distortion=\"0.298417\", orientation=65, skew=\"0.310367\", color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)
    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"hexagon\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)
    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"tab\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", clientName)

    //fmt.Fprintf(f, "    client_name [label=\"    %s    \" shape=\"component\", style=\"filled\", width=3.0, fixedsize=true, color=\"#b22800\" fillcolor=\"#eddad5\" fontsize=24];\n", r.rootNode)

    
    for _, subnet := range topList {
        for _, host := range subnet.Hosts {
            if host.Hide {
                continue
            }
            for _, port := range host.Ports {
                for _, cert := range port.Certs {
                    certNode := cert.ID
                    strCert := []string{}
                    strCert = append(strCert, cert.CN)
                    for _, alt := range cert.AlternateNames {
                        strCert = append(strCert, alt)
                    }
                
                    fmt.Fprintf(f, "    \"%s\" [label=\"%s\" shape=note fillcolor=\"#cab2d6\"]\n", certNode, strings.Join(strCert, "\n"))
                }

            }
        }
    }

    ipCount := 0
    for i, subnet := range topList {
        for _, host := range subnet.Hosts {
            if host.Hide {
                continue
            }
            for _, port := range host.Ports {                    
                if len(port.Certs) > 0 {
                    for _, cert := range port.Certs {
                        certNode := cert.ID
                        subnetName := fmt.Sprintf("c_%s_subnet_%d", certNode, i)
                        ipNode := fmt.Sprintf("%s_ip%d", subnetName, ipCount)
                        portNode := fmt.Sprintf("%s_p%d", ipNode, port.Port)

                        fmt.Fprintf(f, "    \"%s\" [shape=signature color=\"#445383\" fillcolor=\"#708bce\" label=\"%s\"]\n", subnetName, subnet.Subnet)
                        fmt.Fprintf(f, "    \"%s\" -> \"%s\" [label=\"\" color=\"#6a3d9a\"]\n", certNode, subnetName)

                        fmt.Fprintf(f, "    %s [ shape=box label=\"%s\" ];\n", ipNode, host.Name)
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

func (r *DataReader) GetCertificates() []models.Cert {
    certificates := []models.Cert{}

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
                    certificates = append(certificates, models.Cert{
                        ID        : cert.Hash,
                        CN        : tools.FormatCN(cert.Subject),
                    })
                }
            }
        }

        
    }

    return certificates
}

func (r *DataReader) getNmapXML(filePath string) (*nmap.NmapRun, error) {
    xml, err := os.ReadFile(filePath)
    if err != nil {
        return nil, err
    }

    nmapXML, err := nmap.Parse(xml)
    if err != nil {
        if len(xml) < 1024 {
            return nil, err
        }

        log.Warn("XML data is broken, trying to solve that...", "err", err)

        // Check if we can solve the most common issue
        var err2 error
        newText := string(xml[len(xml)-1024:])
        if strings.Contains(newText, "<runstats") && !strings.Contains(newText, "</runstats>") {
            xml = append(xml, []byte("</runstats>")...)
        } 
        if !strings.Contains(newText, "</nmaprun>") {
            xml =  append(xml, []byte("</nmaprun>")...)
        } 
        nmapXML, err2 = nmap.Parse(xml)
        if err2 != nil {
            return nil, err //Return original error
        }
        log.Warn("Issue resolved: XML data has been successfully repaired and loaded.")
    }

    return nmapXML, nil
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
