# Envoy-Go-Waf

Web Application Firewall Go filter built on top of [Coraza](https://github.com/corazawaf/coraza). It can be loaded directly from Envoy.

## Getting started

`go run mage.go` lists all the available commands:

```bash
▶ go run mage.go
Targets:
  build              builds the Coraza goFilter plugin.
  doc                runs godoc, access at http://localhost:6060
  e2e                runs e2e tests with a built plugin against the example deployment.
  ftw                runs ftw tests with a built plugin and Envoy.
  runExample         spins up the test environment, access at http://localhost:8080.

```

### Building the filter

```bash
go run mage.go build
```

You will find the go waf plugin under `./plugin.so`.

### Running the filter in an Envoy process

In order to run the coraza-proxy-wasm we need to spin up an envoy configuration including this as the filter config

```yaml
    ...

    filter_chains:
      - filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
              stat_prefix: ingress_http
              http_filters:
                - name: envoy.filters.http.golang
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.golang.v3alpha.Config
                    library_id: example
                    library_path: /etc/envoy/plugin.so
                    plugin_name: waf-go-envoy
                    plugin_config:
                      "@type": type.googleapis.com/xds.type.v3.TypedStruct
                      value:
                        directives: |
                          {
                            "waf1":{
                                  "simple_directives":[
                                          "SecDefaultAction \"phase:3,log,auditlog,pass\"",
                                          "SecDefaultAction \"phase:4,log,auditlog,pass\"",
                                          "SecDefaultAction \"phase:5,log,auditlog,pass\"",
                                          "SecDebugLogLevel 3",
                                          "SecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\" \nSecRule REQUEST_BODY \"@rx maliciouspayload\" \"id:102,phase:2,t:lowercase,deny\" \nSecRule RESPONSE_HEADERS::status \"@rx 406\" \"id:103,phase:3,t:lowercase,deny\" \nSecRule RESPONSE_BODY \"@contains responsebodycode\" \"id:104,phase:4,t:lowercase,deny\""
                                    ],
                                  "directives_files":[
                                          "/etc/envoy/rules/coraza-demo.conf",
                                          "/etc/envoy/rules/crs-setup-demo.conf", 
                                          "/etc/envoy/rules/crs/*.conf"
                                    ]
                              }
                          }
                        default_directive: "waf1"
                        host_directive_map: |
                          {
                            "foo.example.com":"waf1",
                            "bar.example.com":"waf1"
                          }
```

### Using CRS

you can use the [Core Rule Set](https://github.com/coreruleset/coreruleset) by mounting it to the container or you can also mount other rules


#### Recommendations using CRS with proxy-wasm

- In order to mitigate as much as possible malicious requests (or connections open) sent upstream, it is recommended to keep the [CRS Early Blocking](https://coreruleset.org/20220302/the-case-for-early-blocking/) feature enabled (SecAction [`900120`](./wasmplugin/rules/crs-setup.conf.example)).

### Running go-ftw (CRS Regression tests)

The following command runs the [go-ftw](https://github.com/coreruleset/go-ftw) test suite against the filter with the CRS fully loaded.

```bash
go run mage.go ftw
```

Take a look at its config file [ftw.yml](./ftw/ftw.yml) for details about tests currently excluded.

One can also run a single test by executing:

```bash
FTW_INCLUDE=920410 go run mage.go ftw
```