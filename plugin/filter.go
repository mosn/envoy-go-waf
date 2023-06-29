package main

import (
	"fmt"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/api"
	"net"
	"net/http"
	"runtime"
	"strconv"
)

type filter struct {
	callbacks    api.FilterCallbackHandler
	conf         configuration
	wafMaps      wafMaps
	tx           types.Transaction
	logger       debuglog.Logger
	httpProtocol string
}

func (f *filter) DecodeHeaders(headerMap api.RequestHeaderMap, endStream bool) api.StatusType {
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
		f.logger = f.tx.DebugLogger()
	} else {
		waf, ok := f.conf.wafMaps[f.conf.defaultDirective]
		if !ok {
			return api.Continue
		}
		f.tx = waf.NewTransaction()
		f.logger = f.tx.DebugLogger()
	}
	tx := f.tx
	//X-Coraza-Rule-Engine: Off 用于检测是否禁用了规则引擎，有可能这个没有作用
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	//拿到远程请求的地址
	srcIP, srcPortString, err := net.SplitHostPort(f.callbacks.StreamInfo().DownstreamRemoteAddress())
	if err != nil {
		f.logger.Error().Err(err).Msg("RemoteAddress formatting error")
		f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "RemoteAddress formatting error")
		return api.LocalReply
	}
	srcPort, err := strconv.Atoi(srcPortString)
	if err != nil {
		f.logger.Error().Err(err).Msg("RemotePort formatting error")
		f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "RemotePort formatting error")
		return api.LocalReply
	}
	destIP, destPortString, err := net.SplitHostPort(f.callbacks.StreamInfo().DownstreamLocalAddress())
	if err != nil {
		f.logger.Error().Err(err).Msg("LocalAddress formatting error")
		f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "LocalAddress formatting error")
		return api.LocalReply
	}
	destPort, err := strconv.Atoi(destPortString)
	if err != nil {
		f.logger.Error().Err(err).Msg("LocalPort formatting error")
		f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "LocalPort formatting error")
		return api.LocalReply
	}
	tx.ProcessConnection(srcIP, srcPort, destIP, destPort)
	path := headerMap.Path()
	method := headerMap.Method()
	protocol := headerMap.Protocol()
	if len(protocol) == 0 {
		f.logger.Warn().Msg("Get protocol failed")
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
		f.logger.Debug().
			Str("Host", host).
			Err(err).
			Msg("Failed to parse server name from Host")
	}
	tx.SetServerName(server)
	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		f.logger.Error().Msg("ProcessRequestHeaders failed")
		f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "ProcessRequestHeaders failed")
		return api.LocalReply
	}
	return api.Continue
}

func (f *filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	if f.tx == nil {
		return api.Continue
	}
	tx := f.tx
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	if !tx.IsRequestBodyAccessible() {
		f.logger.Debug().Msg("RequestBody Not Accessible,Skipping request body inspection")
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			f.logger.Error().Err(err).Msg("ProcessRequestBody error")
			return api.Continue
		}
		if interruption != nil {
			f.logger.Error().Msg("ProcessRequestBody forbidden")
			f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "ProcessRequestBody forbidden")
			return api.LocalReply
		}
	}
	bodySize := buffer.Len()
	if bodySize > 0 {
		bytes := buffer.Bytes()
		interruption, _, err := tx.WriteRequestBody(bytes)
		if err != nil {
			f.logger.Error().Err(err).Msg("Failed to write request body")
			f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "Failed to write request body")
			return api.LocalReply
		}
		if interruption != nil {
			//TODO:处理打断
			f.logger.Error().Msg("RequestBody is over limit")
			f.callbacks.SendLocalReply(http.StatusBadRequest, "", map[string]string{}, 0, "RequestBody is over limit")
			return api.LocalReply
		}
	}
	if endStream {
		//TODO bug1
		//runtime: mmap(0xc002400000, 0) returned 0x0, 22
		//fatal error: runtime: cannot map pages in arena address space
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			f.logger.Error().Err(err).Msg("ProcessRequestBody error")
			return api.Continue
		}
		if interruption != nil {
			f.logger.Error().Err(err).Msg("ProcessRequestBody failed")
			f.callbacks.SendLocalReply(http.StatusForbidden, "", map[string]string{}, 0, "ProcessRequestBody failed local reply")
			return api.LocalReply
		}
		runtime.GC()
	}
	return api.Continue
}

func (f *filter) DecodeTrailers(trailerMap api.RequestTrailerMap) api.StatusType {
	return api.Continue
}

func (f filter) EncodeHeaders(headerMap api.ResponseHeaderMap, endStream bool) api.StatusType {
	if f.tx == nil {
		return api.Continue
	}
	tx := f.tx
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	return api.Continue
}

func (f *filter) EncodeData(instance api.BufferInstance, endStream bool) api.StatusType {
	return api.Continue
}

func (f *filter) EncodeTrailers(trailerMap api.ResponseTrailerMap) api.StatusType {
	return api.Continue
}

func (f *filter) OnDestroy(reason api.DestroyReason) {
	//TODO:clear
	tx := f.tx
	if tx != nil {
		//TODO:clear
		fmt.Println("tx != nil")
		// ProcessLogging is still called even if RuleEngine is off for potential logs generated before the engine is turned off.
		// Internally, if the engine is off, no log phase rules are evaluated
		f.tx.ProcessLogging()

		_ = f.tx.Close()
		f.logger.Info().Msg("finished")
		//logMemStats()
	}
}

func main() {

}
