package main

import (
	"fmt"
	"github.com/corazawaf/coraza/v3/debuglog"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/api"
	"io"
)

func wafPrinterFactory(callbacks api.FilterCallbackHandler) func(w io.Writer) debuglog.Printer {
	return func(w io.Writer) debuglog.Printer {
		return func(lvl debuglog.Level, message, fields string) {
			switch lvl {
			case debuglog.LevelTrace:
				callbacks.Log(api.Trace, fmt.Sprintf("%s %s", message, fields))
			case debuglog.LevelDebug:
				callbacks.Log(api.Debug, fmt.Sprintf("%s %s", message, fields))
			case debuglog.LevelInfo:
				callbacks.Log(api.Info, fmt.Sprintf("%s %s", message, fields))
			case debuglog.LevelWarn:
				callbacks.Log(api.Warn, fmt.Sprintf("%s %s", message, fields))
			case debuglog.LevelError:
				callbacks.Log(api.Error, fmt.Sprintf("%s %s", message, fields))
			default:
			}
		}
	}
}

func logError(callbacks api.FilterCallbackHandler) func(error ctypes.MatchedRule) {
	return func(error ctypes.MatchedRule) {
		msg := error.ErrorLog(0)
		switch error.Rule().Severity() {
		case ctypes.RuleSeverityEmergency:
			callbacks.Log(api.Critical, msg)
		case ctypes.RuleSeverityAlert:
			callbacks.Log(api.Critical, msg)
		case ctypes.RuleSeverityCritical:
			callbacks.Log(api.Critical, msg)
		case ctypes.RuleSeverityError:
			callbacks.Log(api.Error, msg)
		case ctypes.RuleSeverityWarning:
			callbacks.Log(api.Warn, msg)
		case ctypes.RuleSeverityNotice:
			callbacks.Log(api.Info, msg)
		case ctypes.RuleSeverityInfo:
			callbacks.Log(api.Info, msg)
		case ctypes.RuleSeverityDebug:
			callbacks.Log(api.Debug, msg)
		}
	}
}
