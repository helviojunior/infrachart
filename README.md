# infrachart

## Get last release

Check how to get last release by your Operational Systems procedures here [INSTALL.md](https://github.com/helviojunior/infrachart/blob/main/INSTALL.md)


# Utilization

```
infrachart report dot --from-path ~/Desktop/ -o ~/Desktop/output.dot --filter sec4us
dot -Tpng output.dot -o graph.png
```


```
$ infrachart -h

    Infra
      |
      o-- Enumeration
      |       |\
      |       | \
      |       |  \
      |     Flow Chart
      |
      o-- by M4v3r1ck

Usage:
  infrachart [command]

Examples:

- infrachart report dot --from-path ~/client_data/ --to-file infrachart.dot
- infrachart report dot --from-path ~/client_data/ --to-file infrachart.dot  --type certificates
- infrachart report dot --from-path ~/client_data/enumdns.sqlite3 --to-file infrachart.dot -F
- infrachart report dot --from-path ~/client_data/nmap_file.xml --to-file infrachart.dot


Available Commands:
  help        Help about any command
  report      Work with infrachart reports
  version     Get the infrachart version

Flags:
      --cert-only           Show only host/port with digital certificates
  -P, --from-path strings   The file(s) or directory(ies) to convert from. You can specify multiple values by repeating the flag.
  -h, --help                help for dot
  -p, --port string         Only show specified ports. (Ex: -p22; -p1-65535; -p 53,111,137,21-25,80,139,8080)
  -o, --to-file string      The file to convert to. Must be .dot extension (default "./infrachart.dot")
      --top-ports int       Show <number> most common ports
  -t, --type string         Chart type. (Options: hosts, certificates) (default "hosts")

Global Flags:
      --continue        Continue execution even if some dependencies are missing
      --db-debug-log    Enable debug logging
  -D, --debug-log       Enable debug logging
      --filter string   Comma-separated terms to filter results
  -F, --full            Do not filter out SaaS addresses
      --local-temp      Store the temporary file in the current workspace
  -q, --quiet           Silence (almost all) logging

```

## Use-cases

### Image 1 - All host, ports and certificates

**Note:** This command filtered out SaaS services

```bash
infrachart report dot --from-path ~/Desktop/teste3/ -o chart1.dot --filter sec4us --top-ports 1000
```

![Chart 1](https://github.com/helviojunior/infrachart/blob/main/images/chart1.png "chart 1")


### Image 2 - All host, ports that contains valid certificate

**Note:** This command `filtered out` SaaS services

```bash
infrachart report dot --from-path ~/Desktop/teste3/ -o chart1.dot --filter sec4us --top-ports 1000 --cert-only
```

![Chart 2](https://github.com/helviojunior/infrachart/blob/main/images/chart2.png "chart 2")


### Image 3 - All host, ports that and certificate

**Note:** This command `show` SaaS services

```bash
infrachart report dot --from-path ~/Desktop/teste3/ -o chart3.dot --filter sec4us --top-ports 1000 -F
```

![Chart 3](https://github.com/helviojunior/infrachart/blob/main/images/chart3.png "chart 3")


### Image 4 - All host, ports that and certificate (view using certificate as center node)

**Note:** This command `filtered out` SaaS services

```bash
infrachart report dot --from-path ~/Desktop/teste3/ -o chart4.dot --filter sec4us --top-ports 1000 --type certificates
```

![Chart 4](https://github.com/helviojunior/infrachart/blob/main/images/chart4.png "chart 4")


## Nmap command 

To generate the Nmap XML with certificate data use the followin parameters

1. `-A` or `--script ssl-cert`
2. `-oX` to save output to a XML

```bash
nmap -Pn -v -T4 -sTV -A -p80,443,8443,3389 10.10.10.10 -oX nmap_1.xml
infrachart report dot --from-path nmap_1.xml --to-file infrachart.dot
```

## Disclaimer

This tool is intended for educational purpose or for use in environments where you have been given explicit/legal authorization to do so.