package cmd

import (
    "os"
    "errors"
    "fmt"
    "path/filepath"
    "strings"

    "github.com/helviojunior/infrachart/internal/ascii"
    "github.com/helviojunior/infrachart/internal/tools"
    "github.com/helviojunior/infrachart/pkg/readers"
    "github.com/helviojunior/infrachart/pkg/log"
    resolver "github.com/helviojunior/gopathresolver"
    "github.com/spf13/cobra"
)

var conversionCmdExtensions = []string{".sqlite", ".sqlite3", ".db"}
var convertCmdFlags = struct {
    fromPath        string
    fromPathType    string
    toFile          string
    toExt           string
    rootNodeName    string
}{}
var convertCmd = &cobra.Command{
    Use:   "dot",
    Short: "Convert data to Graphviz dot file",
    Long: ascii.LogoHelp(ascii.Markdown(`
# report dot

Convert data to Graphviz dot file.

A --from-path and --to-file must be specified. The extension used for the
specified filenames will be used to determine the conversion direction and
target.`)),
    Example: ascii.Markdown(`
- infrachart report dot --from-path ~/client_data/ --to-file infrachart.dot
- infrachart report dot --from-path ~/client_data/enumdns.sqlite3 --to-file infrachart.dot
`),
    PreRunE: func(cmd *cobra.Command, args []string) error {
        var err error
        
        if convertCmdFlags.fromPath == "" {
            return errors.New("from-path not set")
        }
        if convertCmdFlags.toFile == "" {
            return errors.New("to-file not set")
        }

        convertCmdFlags.fromPath, err = resolver.ResolveFullPath(convertCmdFlags.fromPath)
        if err != nil {
            return err
        }

        convertCmdFlags.toFile, err = resolver.ResolveFullPath(convertCmdFlags.toFile)
        if err != nil {
            return err
        }

        convertCmdFlags.toExt = strings.ToLower(filepath.Ext(convertCmdFlags.toFile))

        if convertCmdFlags.toExt == "" {
            return errors.New("destination files must have extensions")
        }

        if convertCmdFlags.fromPath == convertCmdFlags.toFile {
            return errors.New("source and destination files cannot be the same")
        }

        if convertCmdFlags.toExt != ".dot" {
            return errors.New("unsupported destination file type")
        }

        if convertCmdFlags.fromPathType, err = tools.FileType(convertCmdFlags.fromPath); err != nil {
            return err
        }

        if convertCmdFlags.fromPathType == "file" {

            fromExt := strings.ToLower(filepath.Ext(convertCmdFlags.fromPath))

            if !tools.SliceHasStr(conversionCmdExtensions, fromExt) {
                return errors.New("unsupported source file type")
            }
        }

        return nil
    },
    Run: func(cmd *cobra.Command, args []string) {
        //var ft string
        //var err error

        log.Info("Starting process...")

        reader, err := readers.NewDataReader(convertCmdFlags.rootNodeName, *opts)
        if err != nil {
            log.Error("Error starting data reader", "err", err)
            os.Exit(2)
        }

        if convertCmdFlags.fromPathType == "file" {
            log.Debug("Adding database file", "path", convertCmdFlags.fromPathType)
            reader.AddDatabase(convertCmdFlags.fromPathType)
        }else {

            log.Debug("Checking folder", "path", convertCmdFlags.fromPath)
            entries, err := os.ReadDir(convertCmdFlags.fromPath)
            if err != nil {
                log.Error("Cannot reader path", "path", convertCmdFlags.fromPath, "err", err)
                os.Exit(2)
            }
         
            for _, e := range entries {
                fileFullPath := filepath.Join(convertCmdFlags.fromPath, e.Name())
                fileRelativePath, _ := resolver.ResolveRelativePath(convertCmdFlags.fromPath, filepath.Join(convertCmdFlags.fromPath, e.Name()))
                fileExt := strings.ToLower(filepath.Ext(e.Name()))
                if tools.SliceHasStr(conversionCmdExtensions, fileExt) {
                    log.Debug("Adding database file", "path", fileRelativePath)
                    reader.AddDatabase(fileFullPath)
                }else{
                    log.Debug("Ignoring file", "path", fileRelativePath)
                }
                
            }

        }

        reader.GenerateDotFile(convertCmdFlags.toFile)
        log.Info("Process done!")

        fmt.Printf(ascii.Markdown("# Done!\n\nUse the command `dot -Tpng output.dot -o graph.png` to generate the image"))

    },
}

func init() {
    reportCmd.AddCommand(convertCmd)

    
    convertCmd.Flags().StringVarP(&convertCmdFlags.rootNodeName, "name", "n", "Infra Chart", "The name of Root Node")

    convertCmd.Flags().StringVarP(&convertCmdFlags.fromPath, "from-path", "p", "", "The file to convert from")
    convertCmd.Flags().StringVarP(&convertCmdFlags.toFile, "to-file", "o", "./infrachart.dot", "The file to convert to. Must be .dot extension")

    convertCmd.Flags().StringVarP(&opts.ChartType, "type", "t", "hosts", "Chart type. (Options: hosts, certificates)")
}
