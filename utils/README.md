## Content-Format to Media Types maps

The go maps used to translate Content-Formats to Media Types (and vice-versa) are automatically generated from the IANA [CoRE Parameters](https://www.iana.org/assignments/core-parameters/core-parameters.xhtml) registry.

The automatic extraction depends on [`zek(1)`](https://github.com/miku/zek), which can be installed via:

```shell
go install github.com/miku/zek/cmd/zek@latest
```

To rebuild the go maps ([`../cfmap.go`](../cfmap.go)), do:

```
make all clean
```
