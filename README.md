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
      o-- vdev-dev

Usage:
  infrachart [command]

Examples:

- infrachart report dot --from-path ~/client_data/ --to-file infrachart.dot
- infrachart report dot --from-path ~/client_data/enumdns.sqlite3 --to-file infrachart.dot


Available Commands:
  help        Help about any command
  report      Work with infrachart reports
  version     Get the infrachart version

Flags:
      --db-debug-log   Enable debug logging
  -D, --debug-log      Enable debug logging
  -h, --help           help for infrachart
  -q, --quiet          Silence (almost all) logging

Use "infrachart [command] --help" for more information about a command.

```


## Disclaimer

This tool is intended for educational purpose or for use in environments where you have been given explicit/legal authorization to do so.