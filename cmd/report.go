package cmd

import (
	"regexp"
    "strings"
    "errors"
    "net"
    "fmt"
    "sort"

    "github.com/helviojunior/infrachart/internal/ascii"
    "github.com/helviojunior/infrachart/internal/tools"

    "github.com/helviojunior/infrachart/pkg/log"
    "github.com/spf13/cobra"
)

var rptFilter = []string{}
var reportCmd = &cobra.Command{
    Use:   "report",
    Short: "Work with infrachart reports",
    Long: ascii.LogoHelp(ascii.Markdown(`
# report

Work with infrachart reports.
`)),
    PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
        var err error

        // Annoying quirk, but because I'm overriding PersistentPreRun
        // here which overrides the parent it seems.
        // So we need to explicitly call the parent's one now.
        if err = rootCmd.PersistentPreRunE(cmd, args); err != nil {
            return err
        }

        re := regexp.MustCompile("[^a-zA-Z0-9@-_.]")
        for _, s1 := range rptFilter {

            subnet, err := ExtractSubnet(s1)
            if err != nil {
                return err
            }
            if subnet != nil {
                opts.SubnetFilterList = append(opts.SubnetFilterList, *subnet)
            }else{
                s2 := strings.ToLower(strings.Trim(s1, " "))
                s2 = re.ReplaceAllString(s2, "")
                if s2 != "" {
                    opts.FilterList = append(opts.FilterList, s2)
                }
            }
        }
        // Sort subnets by IP
        sort.Slice(opts.SubnetFilterList, func(i, j int) bool {
            return tools.SubnetToUint32(opts.SubnetFilterList[i]) < tools.SubnetToUint32(opts.SubnetFilterList[j])
        })

        if len(opts.SubnetFilterList) > 0 {
            fl := []string{}
            for _, n := range opts.SubnetFilterList {
                fl = append(fl, n.String())
            }
            log.Warn("Subnet filter list: " + strings.Join(fl, ", "))
        }

        if len(opts.FilterList) > 0 {
            log.Warn("Filter list: " + strings.Join(opts.FilterList, ", "))
        }

        return nil
    },
}

func ExtractSubnet(text string) (*net.IPNet, error) {
    netRe1 := regexp.MustCompile("\\b([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\/(3[0-2]|[12][0-9]|[1-9])\\b")
    netRe2 := regexp.MustCompile("\\b([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\/(255\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\b")
    ipRe := regexp.MustCompile("\\b([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\b")

    // Check if is an CIDR Subnet (xxx.xxx.xxx.xxx/xx)
    mNet1 := netRe1.FindStringSubmatch(text)
    if len(mNet1) > 0 {
        _, subnet, err := net.ParseCIDR(mNet1[0])
        if err != nil {
            return nil, errors.New("Invalid subnet: " + err.Error())
        }
        return subnet, nil
    }

    // Check if is an Netmask Subnet (xxx.xxx.xxx.xxx/255.xxx.xxx.xxx)
    mNet2 := netRe2.FindStringSubmatch(text)
    if len(mNet2) > 0 {
        ip := net.ParseIP(mNet2[1])
        if ip == nil {
            return nil, errors.New(fmt.Sprintf("Invalid subnet ip (%s)", mNet2[0]))
        }
        mask := net.IPMask(net.ParseIP(mNet2[2]).To4())
        if mask == nil {
            return nil, errors.New(fmt.Sprintf("Invalid subnet mask (%s)", mNet2[0]))
        }
        ones, _ := mask.Size()

        cidr := fmt.Sprintf("%s/%d", ip.String(), ones)

        _, subnet, err := net.ParseCIDR(cidr)
        if err != nil {
            return nil, errors.New("Invalid subnet: " + err.Error())
        }
        return subnet, nil
    }

    // Check if is an IP addr
    mIp := ipRe.FindStringSubmatch(text)
    if len(mIp) > 0 {
        ip := net.ParseIP(mIp[0])
        if ip == nil {
            return nil, errors.New(fmt.Sprintf("Invalid ip address (%s)", mIp[0]))
        }
        _, subnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip, 32))
        if err != nil {
            return nil, errors.New(fmt.Sprintf("Invalid ip address (%s): %s", mIp[0], err.Error()))
        }
        return subnet, nil
    }

    return nil, nil
}

func init() {
    rootCmd.AddCommand(reportCmd)

    reportCmd.PersistentFlags().StringSliceVar(&rptFilter, "filter", []string{}, "Filter terms. You can specify multiple values by comma-separated terms or by repeating the flag.")
    reportCmd.PersistentFlags().BoolVarP(&opts.FullChart, "full", "F", false, "Do not filter out SaaS addresses")
}
