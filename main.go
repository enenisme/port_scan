package port_scan

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortScan 存储端口扫描的结果
type PortScan struct {
	Port    int
	State   bool
	Service string
}

// ScanPort 检查单个端口是否开放
func ScanPort(ip string, port int, timeout time.Duration) PortScan {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return PortScan{Port: port, State: false}
	}
	defer conn.Close()
	return PortScan{Port: port, State: true}
}

// ScanPorts 并发扫描多个端口
func ScanPorts(ip string, ports []int) []PortScan {
	var results []PortScan
	var wg sync.WaitGroup
	mutex := &sync.Mutex{}

	// 限制并发数量
	semaphore := make(chan struct{}, 100)

	for _, port := range ports {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(port int) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result := ScanPort(ip, port, 2*time.Second)
			mutex.Lock()
			results = append(results, result)
			mutex.Unlock()
		}(port)
	}

	wg.Wait()
	return results
}

// 从文件读取端口列表
func loadPortsFromFile(filename string) ([]int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ports []int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		port, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
		if err != nil {
			continue
		}
		ports = append(ports, port)
	}
	return ports, scanner.Err()
}

func main() {
	targetIP := "192.168.0.93"

	// 从文件读取端口列表
	ports, err := loadPortsFromFile("common_ports.txt")
	if err != nil {
		fmt.Printf("读取端口列表失败: %v\n", err)
		return
	}

	fmt.Printf("开始扫描 %s 的端口...\n", targetIP)
	results := ScanPorts(targetIP, ports)

	// 显示结果
	fmt.Println("\n扫描结果:")
	for _, result := range results {
		if result.State {
			fmt.Printf("端口 %d 是开放的\n", result.Port)
		}
	}
}
