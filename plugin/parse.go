package main

import (
	"errors"
	"fmt"
	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"
	jsoniter "github.com/json-iterator/go"
	"google.golang.org/protobuf/types/known/anypb"
	"os"
	"strings"
)

func init() {
	http.RegisterHttpFilterConfigFactoryAndParser("waf-go-envoy", configFactory, &parser{})
}

type parser struct {
}

type configuration struct {
	directives       WafDirectives
	defaultDirective string
	hostDirectiveMap HostDirectiveMap
	wafMaps          wafMaps
	auditLogPath     string
}

type wafMaps map[string]coraza.WAF

type WafDirectives map[string]Directives

type Directives struct {
	SimpleDirectives []string `json:"simple_directives"`
	DirectivesFiles  []string `json:"directives_files"`
}

type HostDirectiveMap map[string]string

func (p parser) Parse(any *anypb.Any) (interface{}, error) {
	configStruct := &xds.TypedStruct{}
	if err := any.UnmarshalTo(configStruct); err != nil {
		return nil, err
	}
	v := configStruct.Value
	var config configuration
	//TODO find a more fast way
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	if directivesString, ok := v.AsMap()["directives"].(string); ok {
		var wafDirectives WafDirectives
		err := json.UnmarshalFromString(directivesString, &wafDirectives)
		if err != nil {
			return nil, err
		}
		if len(wafDirectives) == 0 {
			return nil, errors.New("directives is empty")
		}
		config.directives = wafDirectives
	} else {
		return nil, errors.New("directives is not exist")
	}
	if defaultDirectiveString, ok := v.AsMap()["default_directive"].(string); ok {
		_, ok := config.directives[defaultDirectiveString]
		if !ok {
			return nil, errors.New("default_directive is not exist")
		}
		config.defaultDirective = defaultDirectiveString
	} else {
		return nil, errors.New("default_directive is not exist")
	}

	//最好只是在ftw测试的时候使用
	if auditLogPath, ok := v.AsMap()["audit_log_path"].(string); ok {
		config.auditLogPath = auditLogPath
	}

	if hostDirectiveMapString, ok := v.AsMap()["host_directive_map"].(string); ok {
		hostDirectiveMap := make(HostDirectiveMap)
		err := json.UnmarshalFromString(hostDirectiveMapString, &hostDirectiveMap)
		if err != nil {
			return nil, err
		}
		for host, rule := range hostDirectiveMap {
			_, ok := config.directives[rule]
			if !ok {
				return nil, errors.New(fmt.Sprintf("The rule corresponding to %s does not exist", host))
			}
		}
		config.hostDirectiveMap = hostDirectiveMap
		wafMaps := make(wafMaps)
		for wafName, wafRules := range config.directives {
			wafConfig := coraza.NewWAFConfig()
			if len(config.auditLogPath) != 0 {
				wafConfig = wafConfig.WithErrorCallback(logError(config.auditLogPath))
			}
			wafConfig = wafConfig.WithDirectives(strings.Join(wafRules.SimpleDirectives, "\n"))
			for _, val := range wafRules.DirectivesFiles {
				wafConfig = wafConfig.WithDirectivesFromFile(val)
			}
			waf, err := coraza.NewWAF(wafConfig)
			if err != nil {
				panic(fmt.Sprintf("%s mapping waf init error", wafName))
			}
			wafMaps[wafName] = waf
		}
		config.wafMaps = wafMaps
	}
	return &config, nil
}

func (p parser) Merge(parentConfig interface{}, childConfig interface{}) interface{} {
	panic("TODO")
}

func logError(logPath string) func(error ctypes.MatchedRule) {
	if _, err := os.Stat(logPath); err != nil {
		if os.IsNotExist(err) {
			_, err := os.Create(logPath)
			if err != nil {
				panic(fmt.Sprintf("create auditLog error"))
			}
		}
	}
	return func(error ctypes.MatchedRule) {
		file, err := os.OpenFile(logPath, os.O_RDWR, 0666)
		if err != nil {
			panic(fmt.Sprintf("open auditLog error"))
		}
		defer file.Close()
		msg := error.ErrorLog(0)
		switch error.Rule().Severity() {
		case ctypes.RuleSeverityEmergency:
			file.WriteString(fmt.Sprintf("[Critical] msg=%s\n", msg))
		case ctypes.RuleSeverityAlert:
			file.WriteString(fmt.Sprintf("[Critical] msg=%s\n", msg))
		case ctypes.RuleSeverityCritical:
			file.WriteString(fmt.Sprintf("[Critical] msg=%s\n", msg))
		case ctypes.RuleSeverityError:
			file.WriteString(fmt.Sprintf("[Error] msg=%s\n", msg))
		case ctypes.RuleSeverityWarning:
			file.WriteString(fmt.Sprintf("[Warn] msg=%s\n", msg))
		case ctypes.RuleSeverityNotice:
			file.WriteString(fmt.Sprintf("[Info] msg=%s\n", msg))
		case ctypes.RuleSeverityInfo:
			file.WriteString(fmt.Sprintf("[Info] msg=%s\n", msg))
		case ctypes.RuleSeverityDebug:
			file.WriteString(fmt.Sprintf("[Debug] msg=%s\n", msg))
		}
	}
}
