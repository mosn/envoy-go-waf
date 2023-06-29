package main

import (
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/api"
	"strconv"
)

func BuildLoggerMessage(level api.LogType) logMessage {
	buff := make([]byte, 0)
	return &defaultMessage{level: level, buff: buff}
}

type logMessage interface {
	msg(msg string) string
	str(key, val string) logMessage
	err(err error) logMessage
}

type defaultMessage struct {
	level api.LogType
	buff  []byte
}

func (d *defaultMessage) msg(msg string) string {
	if len(msg) == 0 {
		return string(d.buff)
	}
	d.buff = append(d.buff, ' ')
	d.buff = append(d.buff, "msg="...)
	d.buff = append(d.buff, msg...)
	return string(d.buff)
}

func (d *defaultMessage) str(key, val string) logMessage {
	d.buff = append(d.buff, ' ')
	d.buff = append(d.buff, key...)
	d.buff = append(d.buff, '=')
	d.buff = append(d.buff, strconv.Quote(val)...)
	return d
}

func (d *defaultMessage) err(err error) logMessage {
	if err == nil {
		return d
	}
	d.buff = append(d.buff, "error=\""...)
	d.buff = append(d.buff, err.Error()...)
	d.buff = append(d.buff, "\""...)
	return d
}
