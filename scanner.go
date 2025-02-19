package port_scan

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Scanner struct {
	timeout time.Duration
}

func NewScanner(timeout time.Duration) *Scanner {
	return &Scanner{
		timeout: timeout,
	}
}

// LoadPortsFromFile 从文件加载端口列表
func (s *Scanner) LoadPortsFromFile(filename string) ([]int, error) {
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

// ScanPorts 扫描指定IP的多个端口
func (s *Scanner) ScanPorts(ip string, ports []int) []PortScan {
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

			result := ScanPort(ip, port, s.timeout)
			mutex.Lock()
			results = append(results, result)
			mutex.Unlock()
		}(port)
	}

	wg.Wait()
	return results
}
