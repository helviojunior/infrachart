package cmd

import (


    "github.com/helviojunior/infrachart/internal/ascii"
    "github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
    Use:   "report",
    Short: "Work with infrachart reports",
    Long: ascii.LogoHelp(ascii.Markdown(`
# report

Work with infrachart reports.
`)),
}

func init() {
    rootCmd.AddCommand(reportCmd)
}
