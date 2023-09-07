package main

import (
	"bytes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"net"
	"net/http"
	"strconv"
)

type filter struct {
	callbacks           api.FilterCallbackHandler
	conf                configuration
	wafMaps             wafMaps
	tx                  types.Transaction
	httpProtocol        string
	isInterruption      bool
	processRequestBody  bool
	processResponseBody bool
}

func (f *filter) DecodeHeaders(headerMap api.RequestHeaderMap, endStream bool) api.StatusType {
	var host string
	host = headerMap.Host()
	if len(host) == 0 {
		return api.Continue
	}
	waf := f.conf.wafMaps[f.conf.defaultDirective]
	ruleName, ok := f.conf.hostDirectiveMap[host]
	if ok {
		waf = f.conf.wafMaps[ruleName]
	}
	f.tx = waf.NewTransaction()
	tx := f.tx
	//X-Coraza-Rule-Engine: Off  This can be set through the request header
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	srcIP, srcPortString, _ := net.SplitHostPort(f.callbacks.StreamInfo().DownstreamRemoteAddress())
	srcPort, err := strconv.Atoi(srcPortString)
	if err != nil {
		f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("RemotePort formatting error"))
		f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "RemotePort formatting error")
		return api.LocalReply
	}
	destIP, destPortString, _ := net.SplitHostPort(f.callbacks.StreamInfo().DownstreamLocalAddress())
	destPort, err := strconv.Atoi(destPortString)
	if err != nil {
		f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("LocalPort formatting error"))
		f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "LocalPort formatting error")
		return api.LocalReply
	}
	tx.ProcessConnection(srcIP, srcPort, destIP, destPort)
	path := headerMap.Path()
	method := headerMap.Method()
	protocol := headerMap.Protocol()
	//Maybe it's a bug? sometimes you can't get Protocol from Envoy
	if len(protocol) == 0 {
		f.callbacks.Log(api.Warn, BuildLoggerMessage().msg("Get protocol failed"))
		protocol = "HTTP/2.0"
	}
	f.httpProtocol = protocol
	tx.ProcessURI(path, method, protocol)
	headerMap.Range(func(key, value string) bool {
		tx.AddRequestHeader(key, value)
		return true
	})
	tx.AddRequestHeader("Host", host)
	server, _, err := net.SplitHostPort(host)
	if err != nil {
		f.callbacks.Log(api.Info, BuildLoggerMessage().str("Host", host).err(err).msg("Failed to parse server name from Host"))
		f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "Failed to parse server name from Host")
		return api.LocalReply
	}
	tx.SetServerName(server)
	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		f.isInterruption = true
		f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessRequestHeaders failed"))
		f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "Reject because of bad request header")
		return api.LocalReply
	}
	return api.Continue
}

func (f *filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	if f.isInterruption {
		f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "Interruption already handled")
		return api.LocalReply
	}
	if f.processRequestBody {
		return api.Continue
	}
	if f.tx == nil {
		return api.Continue
	}
	tx := f.tx
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	if !tx.IsRequestBodyAccessible() {
		f.callbacks.Log(api.Debug, BuildLoggerMessage().msg("RequestBody Not Accessible,Skipping request body inspection"))
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("ProcessRequestBody error"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessRequestBody forbidden"))
			f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "Reject because of bad request body")
			return api.LocalReply
		}
	}
	bodySize := buffer.Len()
	if bodySize > 0 {
		bytes := buffer.Bytes()
		interruption, _, err := tx.WriteRequestBody(bytes)
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("Failed to write request body"))
			f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "Failed to write request body")
			return api.LocalReply
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Info, BuildLoggerMessage().msg("RequestBody is over limit"))
			f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "RequestBody is over limit")
			return api.LocalReply
		}
	}
	if endStream {
		interruption, err := tx.ProcessRequestBody()
		f.processRequestBody = true
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("ProcessRequestBody error"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessRequestBody failed"))
			f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "ProcessRequestBody failed")
			return api.LocalReply
		}
	}
	return api.Continue
}

func (f *filter) DecodeTrailers(trailerMap api.RequestTrailerMap) api.StatusType {
	return api.Continue
}

func (f filter) EncodeHeaders(headerMap api.ResponseHeaderMap, endStream bool) api.StatusType {
	if f.isInterruption {
		f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "Interruption already handled")
		return api.LocalReply
	}
	if f.tx == nil {
		return api.Continue
	}
	tx := f.tx
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	if !f.processRequestBody {
		f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessRequestBodyInPause3"))
		interruption, err := tx.ProcessRequestBody()
		f.processRequestBody = true
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("ProcessRequestBody error"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessRequestBody failed"))
			f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "ProcessRequestBody failed")
			return api.LocalReply
		}
	}
	headerMap.Range(func(key, value string) bool {
		tx.AddResponseHeader(key, value)
		return true
	})
	code, b := f.callbacks.StreamInfo().ResponseCode()
	if !b {
		code = 0
	}
	interruption := tx.ProcessResponseHeaders(int(code), f.httpProtocol)
	if interruption != nil {
		f.isInterruption = true
		f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessResponseHeader failed"))
		f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "Reject because of bad response header")
		return api.LocalReply
	}
	return api.Continue
}

func (f *filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	if f.isInterruption {
		f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "Interruption already handled")
		return api.LocalReply
	}
	if f.tx == nil {
		return api.Continue
	}
	tx := f.tx
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	if !tx.IsResponseBodyAccessible() {
		f.callbacks.Log(api.Debug, BuildLoggerMessage().msg("ResponseBody Not Accessible,Skipping response body inspection"))
		interruption, err := tx.ProcessResponseBody()
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("ProcessResponseBody error"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessResponseBody forbidden"))
			f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "ProcessResponseBody forbidden")
			return api.LocalReply
		}
	}
	bodySize := buffer.Len()
	if bodySize > 0 {
		ResponseBodyBuffer := buffer.Bytes()
		interruption, _, err := tx.WriteResponseBody(ResponseBodyBuffer)
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("Failed to write response body"))
			f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "Failed to write response body")
			return api.LocalReply
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ResponseBody is over limit"))
			f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "ResponseBody is over limit")
			return api.LocalReply
		}
	}
	if !endStream {
		interruption, err := tx.ProcessResponseBody()
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("ProcessResponseBody error"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.processResponseBody = true
			buffer.Set(bytes.Repeat([]byte("\x00"), bodySize))
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("ProcessResponseBody failed"))
			f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "Reject because of bad response body")
			return api.LocalReply
		}
	}
	return api.Continue
}

func (f *filter) EncodeTrailers(trailerMap api.ResponseTrailerMap) api.StatusType {
	return api.Continue
}

func (f *filter) OnDestroy(reason api.DestroyReason) {
	tx := f.tx
	if tx != nil {
		if !f.processResponseBody {
			_, err := tx.ProcessResponseBody()
			if err != nil {
				f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("Process response body onDestroy error"))
			}
		}
		tx.ProcessLogging()
		_ = tx.Close()
		f.callbacks.Log(api.Info, BuildLoggerMessage().msg("Finished"))
	}
}

func main() {

}
