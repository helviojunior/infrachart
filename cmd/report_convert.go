package cmd

import (
    "os"
    "errors"
    "fmt"
    "path/filepath"
    "strings"
    "os/exec"
    "strconv"
    "regexp"

    "github.com/helviojunior/infrachart/internal/ascii"
    "github.com/helviojunior/infrachart/internal/tools"
    "github.com/helviojunior/infrachart/pkg/readers"
    "github.com/helviojunior/infrachart/pkg/models"
    "github.com/helviojunior/infrachart/pkg/log"
    resolver "github.com/helviojunior/gopathresolver"
    "github.com/spf13/cobra"
)

type PathInfo struct {
    Path string
    Type string
}

var tmpPort string
var topPorts int
var tmpFromPaths       []string
var conversionCmdExtensions = []string{".sqlite", ".sqlite3", ".db", ".xml"}
var convertCmdFlags = struct {
    fromPaths       []PathInfo
    toFile          string
    toExt           string
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
    PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
        var err error

        if err = reportCmd.PersistentPreRunE(cmd, args); err != nil {
            return err
        }

        if tmpPort != "" {
            tmpList := []string{}
            re := regexp.MustCompile("(\\b[0-9]{1,5}(?:-[0-9]{1,5})?\\b)")
            matches := re.FindAllString(tmpPort, -1)
            for _, m := range matches {
                if strings.Contains(m, "-") {
                    p := strings.Split(m, "-")
                    p1, err := strconv.ParseUint(p[0], 10, 32) // base 10, 32-bit range
                    if err != nil {
                        return errors.New("Port filter conversion error: " + err.Error())
                    }
                    p2, err := strconv.ParseUint(p[1], 10, 32) // base 10, 32-bit range
                    if err != nil {
                        return errors.New("Port filter conversion error: " + err.Error())
                    }
                    for i := p1; i <= p2; i++ {
                        if !tools.SliceHasUInt(opts.Ports, uint(i)) {
                            opts.Ports = append(opts.Ports, uint(i))       
                            tmpList = append(tmpList, fmt.Sprintf("%d", i))
                        }
                    }
                }else{
                    num, err := strconv.ParseUint(m, 10, 32) // base 10, 32-bit range
                    if err != nil {
                        return errors.New("Port filter conversion error: " + err.Error())
                    }

                    if !tools.SliceHasUInt(opts.Ports, uint(num)) {
                        opts.Ports = append(opts.Ports, uint(num))       
                        tmpList = append(tmpList, fmt.Sprintf("%d", num))
                    }
                }       
            }

            if len(tmpList) > 0 {
                log.Warn("Port list: " + strings.Join(tmpList, ", "))
            }

        }

        if topPorts > 0 {
            for i := 1; i <= topPorts; i++ {
                if !tools.SliceHasUInt(opts.Ports, uint(i)) {
                    opts.Ports = append(opts.Ports, uint(i))       
                }
            }
            log.Warnf("Filtering top %d ports", topPorts)
        }

        return nil
    },
    PreRunE: func(cmd *cobra.Command, args []string) error {
        var err error
        
        if len(tmpFromPaths) == 0 {
            return errors.New("from-path not set")
        }
        if convertCmdFlags.toFile == "" {
            return errors.New("to-file not set")
        }

        for i, fp := range tmpFromPaths {
            if strings.Trim(fp, " ") == "" {
                return errors.New(fmt.Sprintf("from-path entry %d is empty", i+1))
            }

            fp1, err := resolver.ResolveFullPath(fp)
            if err != nil {
                return err
            }

            if fpt, err := tools.FileType(fp1); err != nil {
                return err
            }else{

                if fpt == "file" {

                    fromExt := strings.ToLower(filepath.Ext(fp1))

                    if !tools.SliceHasStr(conversionCmdExtensions, fromExt) {
                        return errors.New("unsupported source file type: " + fp1)
                    }
                }

                convertCmdFlags.fromPaths = append(convertCmdFlags.fromPaths, PathInfo{
                    Path   : fp1,
                    Type   : fpt,
                })
            }

        }

        convertCmdFlags.toFile, err = resolver.ResolveFullPath(convertCmdFlags.toFile)
        if err != nil {
            return err
        }

        convertCmdFlags.toExt = strings.ToLower(filepath.Ext(convertCmdFlags.toFile))

        if convertCmdFlags.toExt == "" {
            return errors.New("destination files must have extensions")
        }

        if convertCmdFlags.toExt != ".dot" {
            return errors.New("unsupported destination file type")
        }

        return nil
    },
    Run: func(cmd *cobra.Command, args []string) {
        //var ft string
        //var err error

        log.Info("Starting process...")

        reader, err := readers.NewDataReader(*opts)
        if err != nil {
            log.Error("Error starting data reader", "err", err)
            os.Exit(2)
        }

        for _, fp := range convertCmdFlags.fromPaths {
            if fp.Type == "file" {
                log.Debug("Adding database file", "path", fp.Path)
                reader.AddDatabase(fp.Path)
            }else {

                log.Debug("Checking folder", "path", fp.Path)
                entries, err := os.ReadDir(fp.Path)
                if err != nil {
                    log.Error("Cannot reader path", "path", fp.Path, "err", err)
                    os.Exit(2)
                }
             
                for _, e := range entries {
                    fileFullPath := filepath.Join(fp.Path, e.Name())
                    fileRelativePath, _ := resolver.ResolveRelativePath(fp.Path, filepath.Join(fp.Path, e.Name()))
                    fileExt := strings.ToLower(filepath.Ext(e.Name()))
                    if tools.SliceHasStr(conversionCmdExtensions, fileExt) {
                        log.Debug("Adding database file", "path", fileRelativePath)
                        reader.AddDatabase(fileFullPath)
                    }else{
                        log.Debug("Ignoring file", "path", fileRelativePath)
                    }
                    
                }

            }
        }

        log.Info("Generating .dot file")
        err = reader.GenerateDotFile(convertCmdFlags.toFile)
        if err != nil {

            log.Error("Failed to generate .dot file.")
            log.Errorf("%s", err.Error())

            if _, ok := err.(models.NoDataError); ok {
                os.Exit(5)
            }
            
            os.Exit(2)
        }
        log.Infof("Dot file saved at %s", convertCmdFlags.toFile)
        log.Info("Generating PNG image")

        tempFilename := tools.TempFileName(tempFolder, "infrachart_", ".png")
        pngFile := strings.Replace(convertCmdFlags.toFile, convertCmdFlags.toExt, ".png", -1)

        log.Debug("Executing dot command to save temp image", "dst", tempFilename)
        cmdExec := exec.Command("dot", "-Tpng", convertCmdFlags.toFile, "-o", tempFilename)
        err = cmdExec.Run()
        if err != nil {
            log.Error("Failed to generate image.")
            log.Errorf("%s", err.Error())

            fmt.Printf(ascii.Markdown("# Failed to generate image!\n\nUse the command `dot -Tpng output.dot -o graph.png` to generate the image"))

            os.Exit(3)
        }else{
            log.Debug("Adding a software label to the image")
            err = tools.AddDefaultVersion(tempFilename, pngFile)
            if err != nil {
                log.Debug("Fail to add label, trying to rename temp file to final file", "err", err)
                err = os.Rename(tempFilename, pngFile)
                if err != nil {
                    log.Error("Failed to generate image.")
                    log.Errorf("%s", err.Error())

                    fmt.Printf(ascii.Markdown("# Failed to generate image!\n\nUse the command `dot -Tpng output.dot -o graph.png` to generate the image"))

                    os.Exit(3)
                }
            }
            log.Infof("Png file saved at %s", pngFile)
        }

    },
}

func init() {
    reportCmd.AddCommand(convertCmd)

    convertCmd.Flags().StringSliceVarP(&tmpFromPaths, "from-path", "P", []string{}, "The file(s) or directory(ies) to convert from. You can specify multiple values by repeating the flag.")

    convertCmd.Flags().StringVarP(&convertCmdFlags.toFile, "to-file", "o", "./infrachart.dot", "The file to convert to. Must be .dot extension")

    convertCmd.Flags().StringVarP(&opts.ChartType, "type", "t", "hosts", "Chart type. (Options: hosts, certificates)")
    
    convertCmd.Flags().StringVarP(&tmpPort, "port", "p", "", "Only show specified ports. (Ex: -p22; -p1-65535; -p 53,111,137,21-25,80,139,8080)")
    convertCmd.Flags().IntVar(&topPorts, "top-ports", 0, "Show <number> most common ports")
    
    convertCmd.PersistentFlags().BoolVar(&opts.CertOnly, "cert-only", false, "Show only host/port with digital certificates")
    
}
