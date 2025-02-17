package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Scan an IP to check if it's alive (Ping alternative)
func scanIP(ip string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, 80), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Scan open ports on a given IP
func scanPorts(ip string, ports []int, timeout time.Duration) []int {
	var openPorts []int
	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}
	return openPorts
}

// Get local network prefix (e.g., 192.168.1.)
func getLocalNetwork() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			ip := ipNet.IP.String()
			parts := strings.Split(ip, ".")
			if len(parts) == 4 {
				return fmt.Sprintf("%s.%s.%s.", parts[0], parts[1], parts[2]), nil
			}
		}
	}
	return "", fmt.Errorf("no local network found")
}

func main() {
	fmt.Println("Scanning local network for active devices...")

	networkPrefix, err := getLocalNetwork()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	timeout := 500 * time.Millisecond       // Adjust scan speed
	portsToScan := []int{22, 80, 443, 8080} // Common ports
	activeDevices := []string{}

	// Scan IPs in the local network (e.g., 192.168.1.1 - 192.168.1.254)
	for i := 1; i <= 254; i++ {
		ip := fmt.Sprintf("%s%d", networkPrefix, i)
		if scanIP(ip, timeout) {
			fmt.Printf("Device found: %s\n", ip)
			activeDevices = append(activeDevices, ip)
		}
	}

	// Scan open ports on found devices
	fmt.Println("\nScanning for open ports...")
	results := []string{}
	for _, ip := range activeDevices {
		openPorts := scanPorts(ip, portsToScan, timeout)
		if len(openPorts) > 0 {
			result := fmt.Sprintf("%s - Open Ports: %v", ip, openPorts)
			fmt.Println(result)
			results = append(results, result)
		}
	}

	// Save results to a file
	if len(results) > 0 {
		file, _ := os.Create("scan_results.txt")
		defer file.Close()
		file.WriteString(strings.Join(results, "\n"))
		fmt.Println("\nScan results saved to scan_results.txt")
	} else {
		fmt.Println("\nNo open ports found.")
	}
}
