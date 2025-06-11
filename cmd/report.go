package cmd

import (
	"regexp"
    "strings"

    "github.com/helviojunior/infrachart/internal/ascii"
    
    "github.com/helviojunior/infrachart/pkg/log"
    "github.com/spf13/cobra"
)

var rptFilter = ""
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
        s := strings.Split(rptFilter, ",")
        for _, s1 := range s {
            s2 := strings.ToLower(strings.Trim(s1, " "))
            s2 = re.ReplaceAllString(s2, "")
            if s2 != "" {
                opts.FilterList = append(opts.FilterList, s2)
            }
        }
        
        if len(opts.FilterList) > 0 {
            log.Warn("Filter list: " + strings.Join(opts.FilterList, ", "))
        }

        return nil
    },
}

func init() {
    rootCmd.AddCommand(reportCmd)

    reportCmd.PersistentFlags().StringVar(&rptFilter, "filter", "", "Comma-separated terms to filter results")
}
