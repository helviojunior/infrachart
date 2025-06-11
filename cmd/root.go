package cmd

import (
	"os"
	"fmt"
	"os/signal"
    "syscall"
    "time"

	"github.com/helviojunior/infrachart/internal/ascii"
	"github.com/helviojunior/infrachart/pkg/log"
	"github.com/helviojunior/infrachart/pkg/readers"
    resolver "github.com/helviojunior/gopathresolver"
	"github.com/spf13/cobra"
)

var workspacePath string
var opts = &readers.Options{}
var rootCmd = &cobra.Command{
	Use:   "infrachart",
	Short: "infrachart is a modular chart generator",
	Long:  ascii.Logo(),
	Example: `
- infrachart report dot --from-path ~/client_data/ --to-file infrachart.dot
- infrachart report dot --from-path ~/client_data/enumdns.sqlite3 --to-file infrachart.dot
`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		
	    if cmd.CalledAs() != "version" && !opts.Logging.Silence {
			fmt.Println(ascii.Logo())
		}

		if opts.Logging.Silence {
			log.EnableSilence()
		}

		if opts.Logging.Debug && !opts.Logging.Silence {
			log.EnableDebug()
			log.Debug("debug logging enabled")
		}

		workspacePath, err = resolver.ResolveFullPath(".")
        if err != nil {
            return err
        }

		return nil
	},
}

func Execute() {
	
	ascii.SetConsoleColors()

	c := make(chan os.Signal)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        ascii.ClearLine()
        fmt.Fprintf(os.Stderr, "\r\n")
        ascii.ClearLine()
        ascii.ShowCursor()
        log.Warn("interrupted, shutting down...                            ")
        ascii.ClearLine()
        fmt.Printf("\n")
        os.Exit(2)
    }()

	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SilenceErrors = true
	err := rootCmd.Execute()
	if err != nil {
		var cmd string
		c, _, cerr := rootCmd.Find(os.Args[1:])
		if cerr == nil {
			cmd = c.Name()
		}

		v := "\n"

		if cmd != "" {
			v += fmt.Sprintf("An error occured running the `%s` command\n", cmd)
		} else {
			v += "An error has occured. "
		}

		v += "The error was:\n\n" + fmt.Sprintf("```%s```", err)
		fmt.Println(ascii.Markdown(v))

		os.Exit(1)
	}

	//Time to wait the logger flush
	time.Sleep(time.Second/4)
    ascii.ShowCursor()
    fmt.Printf("\n")
}

func init() {
	
	rootCmd.PersistentFlags().BoolVarP(&opts.Logging.Debug, "debug-log", "D", false, "Enable debug logging")
	rootCmd.PersistentFlags().BoolVar(&opts.Logging.Debug, "db-debug-log", false, "Enable debug logging")
	rootCmd.PersistentFlags().BoolVarP(&opts.Logging.Silence, "quiet", "q", false, "Silence (almost all) logging")
	    
}
