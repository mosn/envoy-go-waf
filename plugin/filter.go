package main

import (
	"github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/api"
	"net"
	"net/http"
	"runtime"
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
	f.callbacks.Log(api.Info, BuildLoggerMessage(api.Info).msg("DecodeHeaders"))
	var host string
	exist := true
	host = headerMap.Host()
	if len(host) == 0 {
		host, exist = headerMap.Get("host")
		if !exist {
			return api.Continue
		}
	}
	ruleName, ok := f.conf.hostDirectiveMap[host]
	if ok {
		waf, ok := f.conf.wafMaps[ruleName]
		if !ok {
			return api.Continue
		}
		f.tx = waf.NewTransaction()
	} else {
		waf, ok := f.conf.wafMaps[f.conf.defaultDirective]
		if !ok {
			return api.Continue
		}
		f.tx = waf.NewTransaction()
	}
	tx := f.tx
	//X-Coraza-Rule-Engine: Off 用于检测是否禁用了规则引擎，有可能这个没有作用
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	//拿到远程请求的地址
	srcIP, srcPortString, err := net.SplitHostPort(f.callbacks.StreamInfo().DownstreamRemoteAddress())
	if err != nil {
		f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).err(err).msg("RemoteAddress formatting error"))
		f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "RemoteAddress formatting error")
		return api.LocalReply
	}
	srcPort, err := strconv.Atoi(srcPortString)
	if err != nil {
		f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).err(err).msg("RemotePort formatting error"))
		f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "RemotePort formatting error")
		return api.LocalReply
	}
	destIP, destPortString, err := net.SplitHostPort(f.callbacks.StreamInfo().DownstreamLocalAddress())
	if err != nil {
		f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).err(err).msg("LocalAddress formatting error"))
		f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "LocalAddress formatting error")
		return api.LocalReply
	}
	destPort, err := strconv.Atoi(destPortString)
	if err != nil {
		f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).err(err).msg("LocalPort formatting error"))
		f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "LocalPort formatting error")
		return api.LocalReply
	}
	tx.ProcessConnection(srcIP, srcPort, destIP, destPort)
	path := headerMap.Path()
	method := headerMap.Method()
	protocol := headerMap.Protocol()
	if len(protocol) == 0 {
		f.callbacks.Log(api.Warn, BuildLoggerMessage(api.Warn).msg("Get protocol failed"))
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
		f.callbacks.Log(api.Debug, BuildLoggerMessage(api.Debug).str("Host", host).err(err).msg("Failed to parse server name from Host"))
	}
	tx.SetServerName(server)
	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		f.callbacks.Log(api.Info, BuildLoggerMessage(api.Info).msg("change isStop"))
		f.isInterruption = true
		f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).msg("ProcessRequestHeaders failed"))
		f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "ProcessRequestHeaders failed")
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
	f.callbacks.Log(api.Info, BuildLoggerMessage(api.Info).msg("DecodeData"))
	if f.tx == nil {
		return api.Continue
	}
	tx := f.tx
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	if !tx.IsRequestBodyAccessible() {
		f.callbacks.Log(api.Debug, BuildLoggerMessage(api.Debug).msg("RequestBody Not Accessible,Skipping request body inspection"))
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).err(err).msg("ProcessRequestBody error"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).msg("ProcessRequestBody forbidden"))
			f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "ProcessRequestBody forbidden")
			return api.LocalReply
		}
	}
	bodySize := buffer.Len()
	if bodySize > 0 {
		bytes := buffer.Bytes()
		interruption, _, err := tx.WriteRequestBody(bytes)
		if err != nil {
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).err(err).msg("Failed to write request body"))
			f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "Failed to write request body")
			return api.LocalReply
		}
		if interruption != nil {
			//TODO:处理打断
			f.isInterruption = true
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).msg("RequestBody is over limit"))
			f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "RequestBody is over limit")
			return api.LocalReply
		}
	}
	if endStream {
		interruption, err := tx.ProcessRequestBody()
		f.processRequestBody = true
		runtime.GC()
		if err != nil {
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).err(err).msg("ProcessRequestBody error"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).msg("ProcessRequestBody failed"))
			f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "ProcessRequestBody failed")
			return api.LocalReply
		}
	}
	return api.StopAndBuffer
}

func (f *filter) DecodeTrailers(trailerMap api.RequestTrailerMap) api.StatusType {
	return api.Continue
}

func (f filter) EncodeHeaders(headerMap api.ResponseHeaderMap, endStream bool) api.StatusType {
	f.callbacks.Log(api.Info, BuildLoggerMessage(api.Info).msg("EncodeHeaders"))
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
		f.callbacks.Log(api.Info, BuildLoggerMessage(api.Info).msg("processRequestBodyInPause3"))
		interruption, err := tx.ProcessRequestBody()
		f.processRequestBody = true
		runtime.GC()
		if err != nil {
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).err(err).msg("ProcessRequestBody error"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).msg("ProcessRequestBody failed"))
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
		f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).msg("ProcessResponseHeader failed"))
		f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "ProcessResponseHeader failed")
		return api.LocalReply
	}
	return api.Continue
}

func (f *filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	f.callbacks.Log(api.Info, BuildLoggerMessage(api.Info).msg("EncodeData"))
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
		f.callbacks.Log(api.Debug, BuildLoggerMessage(api.Debug).msg("ResponseBody Not Accessible,Skipping response body inspection"))
		interruption, err := tx.ProcessResponseBody()
		if err != nil {
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).err(err).msg("ProcessResponseBody error"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).msg("ProcessResponseBody forbidden"))
			f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "ProcessResponseBody forbidden")
			return api.LocalReply
		}
	}
	bodySize := buffer.Len()
	if bodySize > 0 {
		bytes := buffer.Bytes()
		interruption, _, err := tx.WriteResponseBody(bytes)
		if err != nil {
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).err(err).msg("Failed to write response body"))
			f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "Failed to write response body")
			return api.LocalReply
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).msg("ResponseBody is over limit"))
			f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "ResponseBody is over limit")
			return api.LocalReply
		}
	}
	if endStream {
		interruption, err := tx.ProcessResponseBody()
		runtime.GC()
		if err != nil {
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).err(err).msg("ProcessResponseBody error"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.processResponseBody = true
			f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).err(err).msg("ProcessResponseBody failed"))
			f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "ProcessResponseBody failed")
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
			runtime.GC()
			if err != nil {
				f.callbacks.Log(api.Error, BuildLoggerMessage(api.Error).err(err).msg("process response body onDestroy error"))
			}
		}
		tx.ProcessLogging()
		_ = tx.Close()
		f.callbacks.Log(api.Info, BuildLoggerMessage(api.Info).msg("finished"))
	}
}

func main() {

}
