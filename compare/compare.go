package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"time"
	collect "waf-go-envoy/compare/collectPlugin"
)

type testingInfo struct {
	tp90    string
	tp99    string
	realQps float64
}

func main() {
	testWasm()
	testEnvoyGo()
}

// This method is used to test envoy go with qps ranging from 50-1000
func testEnvoyGo() {
	envoyGoStressInfo := make([]*testingInfo, 0, 20)
	hostInfo := make([]*collect.HostInfo, 0, 20)
	//If you want to change the scope of the qps test, you can adjust the for loop
	for i := 50; i <= 1000; i += 50 {
		hostInfoChan := make(chan *collect.HostInfo)
		startEnvoyDockerGO()
		pid, err := getEnvoyPid()
		if err != nil {
			panic(err)
		}
		go startMonitor(pid, hostInfoChan)
		test, err := startStressTest(strconv.Itoa(i))
		if err != nil {
			panic(err)
		}
		info := <-hostInfoChan
		//Add a retry mechanism
		if i < 800 && (test.realQps < float64(i-10) || test.realQps > float64(i+10)) {
			i -= 50
		} else {
			envoyGoStressInfo = append(envoyGoStressInfo, test)
			hostInfo = append(hostInfo, info)
		}
		stopEnvoyDocker()
	}
	open, err := os.OpenFile("./envoyGoTestingData", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic("file path error")
	}
	fmt.Fprintln(open, "realQps    tp90    tp99    mem    cpu")
	for i := 0; i < 20; i++ {
		goStressInfo := envoyGoStressInfo[i]
		info := hostInfo[i]
		fmt.Fprintf(open, "%.2f    %s    %s    %.2f    %.2f\n", goStressInfo.realQps, goStressInfo.tp90, goStressInfo.tp99, info.MemPercent, info.CpuPercent)
	}
}

// This method is used to test wasm with qps ranging from 50-1000
func testWasm() {
	wasmStressInfo := make([]*testingInfo, 0, 20)
	hostInfo := make([]*collect.HostInfo, 0, 20)
	for i := 50; i <= 1000; i += 50 {
		hostInfoChan := make(chan *collect.HostInfo)
		startEnvoyDockerWasm()
		pid, err := getEnvoyPid()
		if err != nil {
			panic(err)
		}
		go startMonitor(pid, hostInfoChan)
		test, err := startStressTest(strconv.Itoa(i))
		if err != nil {
			panic(err)
		}
		info := <-hostInfoChan
		//Add a retry mechanism
		if i < 800 && (test.realQps < float64(i-10) || test.realQps > float64(i+10)) {
			i -= 50
		} else {
			wasmStressInfo = append(wasmStressInfo, test)
			hostInfo = append(hostInfo, info)
		}
		stopEnvoyDocker()
	}
	open, err := os.OpenFile("./envoyWasmTestingData", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic("file path error")
	}
	fmt.Fprintln(open, "realQps    tp90    tp99    mem    cpu")
	for i := 0; i < 20; i++ {
		wasmInfo := wasmStressInfo[i]
		info := hostInfo[i]
		fmt.Fprintf(open, "%.2f    %s    %s    %.2f    %.2f\n", wasmInfo.realQps, wasmInfo.tp90, wasmInfo.tp99, info.MemPercent, info.CpuPercent)
	}
}

// Test wasm by input qps
func testWasmOne(qps int) (*testingInfo, *collect.HostInfo) {
	hostInfoChan := make(chan *collect.HostInfo)
	startEnvoyDockerWasm()
	pid, err := getEnvoyPid()
	if err != nil {
		panic(err)
	}
	go startMonitor(pid, hostInfoChan)
	test, err := startStressTest(strconv.Itoa(qps))
	if err != nil {
		panic(err)
	}
	info := <-hostInfoChan
	stopEnvoyDocker()
	s := fmt.Sprintf("%.2f    %s    %s    %.2f    %.2f\n", test.realQps, test.tp90, test.tp99, info.MemPercent, info.CpuPercent)
	fmt.Println(s)
	return test, info
}

func startEnvoyDockerGO() {
	command := exec.Command("docker", "run", "--rm", "-d", "-e", "GODEBUG=cgocheck=0", "-v", "./envoy_go/envoy.yaml:/etc/envoy/envoy.yaml", "-v", "./envoy_go/plugin.so:/etc/envoy/plugin.so", "-v", "./../plugin/rules:/etc/envoy/rules", "-p", "10000:10000", "envoyproxy/envoy:contrib-dev", "envoy", "-c", "/etc/envoy/envoy.yaml")
	_, err := command.CombinedOutput()
	if err != nil {
		panic(err)
	}
	time.Sleep(time.Second * 2)
}

func startEnvoyDockerWasm() {
	command := exec.Command("docker", "run", "--rm", "-d", "-v", "./wasm/envoy-config.yaml:/etc/envoy/envoy.yaml", "-v", "./wasm/main.wasm:/etc/envoy/main.wasm", "-p", "10000:10000", "envoyproxy/envoy:contrib-dev", "envoy", "-c", "/etc/envoy/envoy.yaml")
	_, err := command.CombinedOutput()
	if err != nil {
		panic(err)
	}
	time.Sleep(time.Second * 2)
}

func stopEnvoyDocker() {
	time.Sleep(time.Second * 2)
	command := exec.Command("docker", "ps")
	output, err := getOutput(command)
	if err != nil {
		panic(err)
	}
	split := bytes.Split(output, []byte("\n"))
	var containerId string
	for _, i2 := range split {
		if bytes.Contains(i2, []byte("envoyproxy/envoy")) {
			containnerSplit := bytes.Split(i2, []byte(" "))
			containerId = string(containnerSplit[0])
			break
		}
	}
	stopCommand := exec.Command("docker", "stop", containerId)
	_, err = stopCommand.CombinedOutput()
	if err != nil {
		panic(err)
	}
}

func getEnvoyPid() (int, error) {
	command := exec.Command("ps", "-ef")
	commandVGrep := exec.Command("grep", "-v", "grep")
	commandVDocker := exec.Command("grep", "-v", "docker")
	commandPGrep := exec.Command("pgrep", "envoy")
	var err error
	commandVGrep.Stdin, err = command.StdoutPipe()
	if err != nil {
		return 0, err
	}
	commandVDocker.Stdin, err = commandVGrep.StdoutPipe()
	if err != nil {
		return 0, err
	}
	commandPGrep.Stdin, err = commandVDocker.StdoutPipe()
	if err != nil {
		return 0, err
	}
	output, err := getOutput(commandPGrep)
	if err != nil {
		panic(err)
	}
	atoi, err := strconv.Atoi(string(bytes.TrimSpace(output)))
	if err != nil {
		return 0, err
	}
	return atoi, nil
}

func startMonitor(pid int, infoChan chan<- *collect.HostInfo) error {
	newMonitor, err := collect.NewMonitor(int32(pid), time.Second*15, "", false)
	if err != nil {
		return err
	}
	info := newMonitor.CollectInfo(1)
	infoChan <- info[0]
	return nil
}

func startStressTest(qps string) (*testingInfo, error) {
	command := exec.Command("./wrk/wrk", "-t", "4", "-c", "400", "-d", "30s", "-R", qps, "--latency", "http://localhost:10000/ping")
	output, err := getOutput(command)
	s := string(output)
	fmt.Println(s)
	if err != nil {
		return nil, err
	}
	info := &testingInfo{}
	split := bytes.Split(output, []byte("\n"))
	for _, i2 := range split {
		if bytes.Contains(i2, []byte("90.000%")) {
			splitTp90 := bytes.Split(i2, []byte(" "))
			for i := len(splitTp90) - 1; i >= 0; i-- {
				tp90 := splitTp90[i]
				if len(tp90) != 0 {
					info.tp90 = string(bytes.TrimSpace(tp90))
					break
				}
			}
		}
		if bytes.Contains(i2, []byte("99.000%")) {
			splitTp99 := bytes.Split(i2, []byte(" "))
			for i := len(splitTp99) - 1; i >= 0; i-- {
				tp99 := splitTp99[i]
				if len(tp99) != 0 {
					info.tp99 = string(bytes.TrimSpace(tp99))
					break
				}
			}
		}
		if bytes.Contains(i2, []byte("Requests/sec:")) {
			splitQps := bytes.Split(i2, []byte(" "))
			for i := len(splitQps) - 1; i >= 0; i-- {
				qps := splitQps[i]
				if len(qps) != 0 {
					info.realQps, err = strconv.ParseFloat(string(qps), 64)
					if err != nil {
						return nil, err
					}
					break
				}
			}
		}
	}
	return info, nil
}

func getOutput(command *exec.Cmd) ([]byte, error) {
	var stdout io.ReadCloser
	var err error
	if stdout, err = command.StdoutPipe(); err != nil {
		return nil, err
	}
	defer stdout.Close()
	if err = command.Start(); err != nil {
		return nil, err
	}
	var all []byte
	if all, err = ioutil.ReadAll(stdout); err != nil {
		return nil, err
	}
	return all, nil
}
