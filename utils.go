package main

import (
	"bytes"
	"encoding/gob"
	"log"
	"os"
	"strconv"

	"github.com/CRASH-Tech/dns-operator/cmd/common"
	//"github.com/CRASH-Tech/dns-operator/cmd/kubernetes/api/v1alpha1"
)

func getStringEnv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}

	return value
}

func getIntEnv(key string, fallback int) int {
	value := os.Getenv(key)

	if len(value) == 0 {
		return fallback
	}
	intValue, err := strconv.Atoi(value)
	if err != nil {
		log.Panicf("cannot parse environment variable as integer. %s %v", key, value)
	}

	return intValue
}

func getBoolEnv(key string, fallback bool) bool {
	value := os.Getenv(key)

	if len(value) == 0 {
		return fallback
	}

	if value == "true" {
		return true
	} else {
		return false
	}
}

func readConfig() (common.Config, error) {
	config := common.Config{}

	config.LISTEN_ADDRESS = getStringEnv("LISTEN_ADDRESS", "[::]")
	config.LISTEN_TCP_PORT = getIntEnv("LISTEN_TCP_PORT", 5353)
	config.LISTEN_UDP_PORT = getIntEnv("LISTEN_UDP_PORT", 5353)

	config.LOG_LEVEL = getStringEnv("LOG_LEVEL", "warning") //TODO: CHANGE TO info
	config.LOG_FORMAT = getStringEnv("LOG_FORMAT", "text")

	//config.MAX_PROCS = getIntEnv("MAX_PROCS", 10000)
	config.THREADS = getIntEnv("THREADS", 12)
	config.SO_REUSE_PORTS = getBoolEnv("SO_REUSE_PORTS", true) //TODO: CHECK IT
	config.PARALLEL_QUERIES = getIntEnv("PARALLEL_QUERIES", 3) //TODO: CHECK IT
	config.TIMEOUT_SECONDS = getIntEnv("TIMEOUT_SECONDS", 10)  //TODO: CHECK IT
	config.STATS_SAMPLES = getIntEnv("STATS_SAMPLES", 100)     //TODO: CHECK IT
	config.COMPRESS = getBoolEnv("COMPRESS", true)
	config.ADD_TTL_SECONDS = getIntEnv("ADD_TTL_SECONDS", 1000) //TODO: CHECK IT

	//config.QUEUE_SIZE = getIntEnv("QUEUE_SIZE", 100) //TODO: CHECK IT

	return config, nil
}

func Hash(s interface{}) string {
	var b bytes.Buffer
	gob.NewEncoder(&b).Encode(s)
	return string(b.Bytes())
}

// func cidrHosts(netw string) []string {
// 	// convert string to IPNet struct
// 	_, ipv4Net, err := net.ParseCIDR(netw)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	// convert IPNet struct mask and address to uint32
// 	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
// 	// find the start IP address
// 	start := binary.BigEndian.Uint32(ipv4Net.IP)
// 	// find the final IP address
// 	finish := (start & mask) | (mask ^ 0xffffffff)
// 	// make a slice to return host addresses
// 	var hosts []string
// 	// loop through addresses as uint32.
// 	// I used "start + 1" and "finish - 1" to discard the network and broadcast addresses.
// 	for i := start + 1; i <= finish-1; i++ {
// 		// convert back to net.IPs
// 		// Create IP address of type net.IP. IPv4 is 4 bytes, IPv6 is 16 bytes.
// 		ip := make(net.IP, 4)
// 		binary.BigEndian.PutUint32(ip, i)
// 		hosts = append(hosts, ip.String())
// 	}
// 	// return a slice of strings containing IP addresses
// 	return hosts
// }

// func isIPInPool(ip net.IP, pool v1alpha1.Pool) bool {
// 	if pool.Spec.Start == "" || pool.Spec.End == "" || ip == nil {
// 		log.Errorf("Cannot find ip: %s-%s", pool.Spec.Start, pool.Spec.End)

// 		return false
// 	}

// 	from16 := net.ParseIP(pool.Spec.Start)
// 	to16 := net.ParseIP(pool.Spec.End)
// 	test16 := ip.To16()

// 	if from16 == nil || to16 == nil || test16 == nil {
// 		log.Error("An ip did not convert to a 16 byte")

// 		return false
// 	}

// 	if bytes.Compare(test16, from16) >= 0 && bytes.Compare(test16, to16) <= 0 {
// 		return true
// 	}

// 	return false
// }
