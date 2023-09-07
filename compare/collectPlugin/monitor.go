package collect

import (
	"errors"
	"fmt"
	"github.com/shirou/gopsutil/process"
	"os"
	"time"
)

type monitor struct {
	monitorPid     int32
	monitorProcess *process.Process
	duration       time.Duration
	writer         *os.File
	isUseWriter    bool
}

type HostInfo struct {
	CpuPercent float64
	MemPercent float32
}

func NewMonitor(pid int32, duration time.Duration, addr string, isUseWriter bool) (*monitor, error) {
	writer := os.Stdout
	if len(addr) != 0 {
		open, err := os.OpenFile(addr, os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			panic("file path error")
		}
		writer = open
	}
	monitor := &monitor{monitorPid: pid, duration: duration, writer: writer, isUseWriter: isUseWriter}
	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}
	for _, newProcess := range processes {
		if newProcess.Pid == pid {
			monitor.monitorProcess = newProcess
			break
		}
	}
	if monitor.monitorProcess == nil {
		return nil, errors.New("pid not exist")
	}
	return monitor, nil
}

func (receiver *monitor) CollectInfo(count int) []*HostInfo {
	infoArray := make([]*HostInfo, 0, count)
	for i := 0; i < count; i++ {
		time.Sleep(receiver.duration)
		percent, err := receiver.monitorProcess.CPUPercent()
		if err != nil {
			panic(err)
		}
		memoryPercent, err := receiver.monitorProcess.MemoryPercent()
		if err != nil {
			panic(err)
		}
		hostinfo := &HostInfo{
			CpuPercent: percent,
			MemPercent: memoryPercent,
		}
		infoArray = append(infoArray, hostinfo)
	}
	if receiver.isUseWriter {
		for i := 0; i < count; i++ {
			fmt.Fprintf(receiver.writer, "%v %v\n", infoArray[i].MemPercent, infoArray[i].CpuPercent)
		}
	}
	receiver.writer.Close()
	return infoArray
}
