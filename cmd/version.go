package cmd

import (
    "fmt"

    "github.com/helviojunior/infrachart/internal/ascii"
    "github.com/helviojunior/infrachart/internal/version"
    "github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
    Use:   "version",
    Short: "Get the infrachart version",
    Long:  ascii.LogoHelp(`Get the infrachart version.`),
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println(ascii.Logo())

        fmt.Println("Author: Helvio Junior (m4v3r1ck)")
        fmt.Println("Source: https://github.com/helviojunior/infrachart")
        fmt.Printf("Version: %s\nGit hash: %s\nBuild env: %s\nBuild time: %s\n\n",
            version.Version, version.GitHash, version.GoBuildEnv, version.GoBuildTime)
    },
}

func init() {
    rootCmd.AddCommand(versionCmd)
}