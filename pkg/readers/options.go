package readers

import (
    //"net/url"
    "net"
)

// Options are global github.com/helviojunior/infrachartinfrachart options
type Options struct {
    // Logging is logging options
    Logging Logging
    
    FilterList []string

    SubnetFilterList []net.IPNet

    ChartType string

    FullChart bool

    StoreTempInWorkspace bool

    CertOnly bool

    Summarize bool

    NoSubnet bool

    Ports []uint

    // Use Port filter just to filter hosts, but show all host ports to chart
    ShowPorts bool
}

// Logging is log related options
type Logging struct {
    // Debug display debug level logging
    Debug bool
    // Debug display debug level logging
    DebugDb bool
    // LogScanErrors log errors related to scanning
    LogScanErrors bool
    // Silence all logging
    Silence bool
}

// NewDefaultOptions returns Options with some default values
func NewDefaultOptions() *Options {
    return &Options{
        Logging: Logging{
            Debug:         true,
            LogScanErrors: true,
        },
        FilterList: []string{},
        FullChart: false,
        StoreTempInWorkspace: false,
        Ports: []uint{
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
        },
    }
}