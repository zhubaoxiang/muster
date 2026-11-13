package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// OpenPort 端口扫描产出：一台主机上一个开放的 TCP 端口
type OpenPort struct {
	Host string
	Port int
}

// DiscoveryPorts 主机发现探活端口：内网机器高概率开放的少数端口，
// 任一连通即判定存活（ICMP 在 Windows 需要原始套接字权限，故用 TCP 探活）
var DiscoveryPorts = []int{22, 80, 135, 443, 445, 3389}

// TopPorts 深度模式默认端口集（内网常见服务，按命中率排序）
var TopPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 443, 445,
	514, 515, 587, 631, 636, 873, 993, 995, 1080, 1099, 1194, 1433, 1521,
	1883, 2049, 2181, 2375, 2379, 3128, 3268, 3306, 3389, 3690, 4444,
	5000, 5432, 5555, 5585, 5666, 5900, 5984, 5985, 6379, 6443, 6666,
	7001, 7002, 7077, 8000, 8001, 8008, 8009, 8010, 8020, 8042, 8060,
	8069, 8080, 8081, 8083, 8088, 8089, 8090, 8161, 8180, 8443, 8500,
	8888, 8649, 8686, 8787, 8983, 9000, 9001, 9002, 9042, 9080, 9090,
	9092, 9100, 9200, 9300, 9418, 9443, 9595, 9999, 10000, 10250,
	11211, 15672, 18080, 18081, 27017, 27018, 28017, 50000, 50070,
	61616,
}

// dialTimeout 单次 TCP 连接超时：内网 RTT 极小，1s 足够且控制扫瘫风险
const dialTimeout = 1 * time.Second

// HostDiscover TCP 探活：对每个目标并发试 DiscoveryPorts，任一开放即存活。
// 返回存活主机列表。
func HostDiscover(ctx context.Context, hosts []string, semSize int,
	progress func(done, total int, current string)) []string {

	sem := make(chan struct{}, semSize)
	var mu sync.Mutex
	var alive []string
	done := 0

	for _, h := range hosts {
		select {
		case <-ctx.Done():
			return alive
		default:
		}
		sem <- struct{}{}
		go func(host string) {
			defer func() {
				<-sem
				mu.Lock()
				done++
				d, t := done, len(hosts)
				mu.Unlock()
				if d%10 == 0 || d == t {
					progress(d, t, host)
				}
			}()
			if hostAlive(ctx, host) {
				mu.Lock()
				alive = append(alive, host)
				mu.Unlock()
			}
		}(h)
	}
	// 等待全部完成（sem 天然限流，这里只需收尾）
	for done < len(hosts) {
		select {
		case <-ctx.Done():
			return alive
		case <-time.After(50 * time.Millisecond):
		}
	}
	return alive
}

func hostAlive(ctx context.Context, host string) bool {
	for _, p := range DiscoveryPorts {
		if tcpOpen(ctx, host, p) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		default:
		}
	}
	return false
}

// ScanPorts TCP Connect 端口扫描：纯 Go 实现，零依赖（Windows 无需 Npcap）。
// 并发池限流 + 1s 超时，内网规模（万级 host-port 组合）秒级到分钟级完成。
func ScanPorts(ctx context.Context, hosts []string, ports []int, semSize int,
	progress func(done, total int, current string)) []OpenPort {

	type job struct {
		host string
		port int
	}
	jobs := make(chan job, 1024)
	out := make(chan OpenPort, 1024)

	total := len(hosts) * len(ports)
	done := 0
	var mu sync.Mutex

	var wg sync.WaitGroup
	for i := 0; i < semSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				select {
				case <-ctx.Done():
					continue
				default:
				}
				if tcpOpen(ctx, j.host, j.port) {
					out <- OpenPort{Host: j.host, Port: j.port}
				}
				mu.Lock()
				done++
				d, t := done, total
				mu.Unlock()
				if d%100 == 0 || d == t {
					progress(d, t, fmt.Sprintf("%s:%d", j.host, j.port))
				}
			}
		}()
	}

feeding:
	for _, h := range hosts {
		for _, p := range ports {
			select {
			case <-ctx.Done():
				break feeding
			case jobs <- job{h, p}:
			}
		}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(out)
	}()

	var open []OpenPort
	for op := range out {
		open = append(open, op)
	}
	return open
}

func tcpOpen(ctx context.Context, host string, port int) bool {
	open, timedOut := tcpDial(ctx, host, port)
	if open || !timedOut {
		return open
	}
	// 超时类失败（SYN 被 DROP）可能是限速/丢包导致的误判，重试一次再判死；
	// 连接拒绝（对端回 RST）是明确关闭，不重试
	open, _ = tcpDial(ctx, host, port)
	return open
}

// tcpDial 返回 (是否开放, 是否超时类失败)
func tcpDial(ctx context.Context, host string, port int) (open, timedOut bool) {
	d := net.Dialer{Timeout: dialTimeout}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = conn.Close()
		return true, false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false, true
	}
	return false, false
}

// serviceTitle 常见端口的服务名，用于 tcp 资产展示
func serviceTitle(p int) string {
	names := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
		80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
		139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
		514: "Syslog", 587: "SMTP", 631: "IPP", 873: "Rsync",
		1433: "MSSQL", 1521: "Oracle", 1883: "MQTT", 2049: "NFS",
		2375: "Docker API", 2379: "etcd", 3128: "Proxy", 3306: "MySQL",
		3389: "RDP", 4444: "Unknown", 5000: "Service", 5432: "PostgreSQL",
		5555: "ADB", 5900: "VNC", 5985: "WinRM", 6379: "Redis",
		6443: "K8s API", 7001: "WebLogic", 8080: "HTTP-Alt",
		8443: "HTTPS-Alt", 8500: "Consul", 8983: "Solr",
		9000: "Service", 9090: "Service", 9100: "Printer",
		9200: "Elasticsearch", 9999: "Service", 10000: "Service",
		10250: "Kubelet", 11211: "Memcached", 15672: "RabbitMQ",
		18080: "Service", 27017: "MongoDB", 50070: "HDFS",
		61616: "ActiveMQ", 8888: "HTTP-Alt",
	}
	if n, ok := names[p]; ok {
		return n
	}
	return fmt.Sprintf("端口 %d", p)
}
