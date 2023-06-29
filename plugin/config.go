package main

import (
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/api"
)

func configFactory(c interface{}) api.StreamFilterFactory {
	conf, ok := c.(*configuration)
	if !ok {
		panic("unexpected config type")
	}
	return func(callbacks api.FilterCallbackHandler) api.StreamFilter {
		return &filter{
			callbacks: callbacks,
			wafMaps:   conf.wafMaps,
			conf:      *conf,
		}
	}
}
