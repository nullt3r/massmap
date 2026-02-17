package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DataDir returns the path to ~/.massmap/ and ensures the directory exists.
// All persistent massmap data (cache, temp files) is stored here.
func DataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to determine home directory: %w", err)
	}

	dir := filepath.Join(home, ".massmap")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create data directory %s: %w", dir, err)
	}

	return dir, nil
}

func YesNoPrompt(label string, def bool) (bool, error) {
	choices := "Y/n"
	if !def {
		choices = "y/N"
	}

	r := bufio.NewReader(os.Stdin)
	var s string

	for {
		fmt.Fprintf(os.Stderr, "%s (%s) ", label, choices)
		var err error
		s, err = r.ReadString('\n')
		if err != nil {
			return def, fmt.Errorf("error reading input: %v", err)
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return def, nil
		}
		s = strings.ToLower(s)
		if s == "y" || s == "yes" {
			return true, nil
		}
		if s == "n" || s == "no" {
			return false, nil
		}
	}
}

func Contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

// IsIP checks if the given string is a valid IP address
func IsIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil
}

// IsCIDR checks if the given string is a valid CIDR notation
func IsCIDR(cidrStr string) bool {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false
	}

	// check if the IP address and mask are valid
	return ipNet != nil && strings.Contains(cidrStr, "/")
}

func IPinCIDR(ip string, cidr string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	address := net.ParseIP(ip)
	if address == nil {
		return false
	}
	return ipnet.Contains(address)
}

func CIDRinCIDR(cidr1 string, cidr2 string) (bool, error) {
	_, subnet1, err := net.ParseCIDR(cidr1)
	if err != nil {
		return false, fmt.Errorf("invalid first CIDR %s: %v", cidr1, err)
	}
	_, subnet2, err := net.ParseCIDR(cidr2)
	if err != nil {
		return false, fmt.Errorf("invalid second CIDR %s: %v", cidr2, err)
	}

	ones1, bits1 := subnet1.Mask.Size()
	ones2, bits2 := subnet2.Mask.Size()
	if bits1 != bits2 {
		return false, fmt.Errorf("CIDR address families differ: %s vs %s", cidr1, cidr2)
	}

	// cidr1 is inside cidr2 if cidr2 contains cidr1's base IP and cidr2 is not more specific.
	return subnet2.Contains(subnet1.IP) && ones2 <= ones1, nil
}

func CIDRtoIPs(cidr string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR format: %v", err)
	}

	var ips []netip.Addr
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr)
	}

	return ips, nil
}

func ReadFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func WriteTargetsToFile(targets *[]string) (string, error) {
	dir, err := DataDir()
	if err != nil {
		return "", err
	}

	file, err := os.CreateTemp(dir, "targets_*.txt")
	if err != nil {
		return "", err
	}
	defer file.Close()

	for _, target := range *targets {
		_, err2 := file.WriteString(target + "\n")
		if err2 != nil {
			return file.Name(), err2
		}
	}

	return file.Name(), err
}

func RunCommand(output bool, cmd ...string) (io.Reader, io.Reader, error) {
	if len(cmd) == 0 {
		return nil, nil, fmt.Errorf("no command provided")
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	command := exec.Command(cmd[0], cmd[1:]...)

	if output {
		command.Stdout = io.MultiWriter(os.Stdout, &stdoutBuf)
		command.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)
	} else {
		command.Stdout = &stdoutBuf
		command.Stderr = &stderrBuf
	}

	err := command.Run()
	if err != nil {
		cmdStr := strings.Join(cmd, " ")
		errOutput := stderrBuf.String()
		if errOutput == "" {
			errOutput = stdoutBuf.String()
		}
		return &stdoutBuf, &stderrBuf, fmt.Errorf("command failed: '%s'\nOutput: %s\nError: %v", cmdStr, errOutput, err)
	}

	return &stdoutBuf, &stderrBuf, nil
}

func IsIPv6(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}

func IsIPv4(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.To4() != nil
}

func JuicyPorts() string {
	return "10000,10006,10009,10010,10026,10037,10047,10048,10080,10087,10089,10093,10100,10136,10141,10187,1022,10256,1026,10283,10443,10477,1050,10543,10652,10691,10776,1080,1099,1100,111,1110,11180,11680,1194,12088,12170,12200,12211,12283,12318,12320,12323,12325,12327,12378,12383,1241,12424,12432,12437,12457,12490,12516,12584,12588,1343,135,1352,139,1433,1434,1444,1521,15672,15673,16004,16017,16029,16036,16052,16059,16063,16082,161,16100,16316,16443,16992,18001,18042,18094,18888,19015,19082,1944,19999,20000,20010,2002,2030,2049,20512,2052,2053,2063,2078,2079,2082,2083,2086,2087,2096,21,2100,2103,2107,2108,2109,2111,2121,2122,2123,2126,21299,2130,2133,2134,2156,2195,2196,22,2200,22206,23,2301,2323,2375,2377,2381,2443,2455,25000,2570,2598,27017,27018,27019,3000,30000,3001,3002,30027,3003,3004,3005,3006,3007,3008,3009,30113,30452,3048,3081,30821,3100,3111,3120,3121,3128,3175,3190,31948,3199,3200,32102,32444,3306,3322,3343,3443,3551,35531,3580,3582,389,4000,40000,40005,4001,4002,4040,4045,4100,4101,4165,4242,443,4431,4432,4433,444,4443,4444,44443,44444,445,4510,4560,457,45886,47001,4712,4848,49443,49682,49694,5000,50001,50002,5001,5004,50080,50202,5022,5044,5060,5061,5080,5090,520,5236,5252,5272,5357,5400,5432,5443,5500,5555,556,5601,5671,5672,5673,5701,5800,5801,5802,5900,5901,5911,5984,5985,5989,60000,6066,6070,632,6346,6347,636,6379,66,6666,6688,7000,7001,7002,7070,7077,7080,7332,7403,7424,7443,7445,7446,7547,7672,7776,7777,7914,7946,7990,7991,7992,7993,7999,80,8000,8001,8002,8003,8007,8008,8009,8012,8022,8043,805,8060,8080,8081,8082,8083,8084,8085,8086,8088,8089,8090,8091,8095,8098,81,8100,8101,8120,8123,8137,8150,8152,8161,8187,82,8200,83,8381,8403,8411,8443,8454,8519,8550,8573,8634,8707,880,8810,8831,8834,8843,8844,8855,8866,8880,8888,8899,8983,8989,9000,9001,9010,9016,9024,9033,9080,9081,9084,9088,9090,9091,9098,9100,9114,9115,9116,9120,9121,9153,9162,9200,9207,9208,9214,9256,9300,9306,9443,9600,9696,9700,9882,9901,9928,9966,9990,9998,9999"
}

func RemoveFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove file %s: %w", path, err)
	}
	return nil
}
