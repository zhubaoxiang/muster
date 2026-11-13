// Package guard 目标护栏：白名单 + 私网锁定。
// 这是引擎发包前的最后一道硬校验，不依赖 UI，UI 被绕过也扫不出去。
//
// 校验模型：
//   - 设置里的白名单条目：无条件入列（它们就是白名单本身）
//   - 本次请求的目标：必须能被「私网范围 + 白名单」吸收，否则拒绝
//   - 公网探测 = 设置解锁 且 请求解锁，两者缺一不可
package guard

import (
	"fmt"
	"net"
	"strings"

	"dianbing/internal/model"
)

// Guard 探测目标护栏
type Guard struct {
	nets        []*net.IPNet // 允许的网段
	singles     []net.IP     // 允许的单个 IP
	domains     []string     // 允许的域名（运行时解析后逐 IP 校验）
	allowPublic bool         // 公网解锁开关（设置解锁 && 请求解锁）
}

// New 构造护栏。settings.Whitelist 里的条目无条件加入白名单。
func New(s model.Settings, requestAllowPublic bool) (*Guard, error) {
	g := &Guard{allowPublic: s.AllowPublic && requestAllowPublic}
	for _, line := range strings.Split(s.Whitelist, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := g.addOne(line, true); err != nil {
			return nil, fmt.Errorf("白名单条目 %q 无效: %w", line, err)
		}
	}
	return g, nil
}

// AddTargets 把本次请求的目标并入护栏（必须被私网/已有白名单吸收）。
func (g *Guard) AddTargets(targets []string) error {
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if err := g.addOne(t, false); err != nil {
			return err
		}
	}
	return nil
}

// addOne 解析单个目标。trusted=true 表示来自白名单设置，直接入列。
func (g *Guard) addOne(t string, trusted bool) error {
	if strings.Contains(t, "/") {
		_, ipnet, err := net.ParseCIDR(t)
		if err != nil {
			return fmt.Errorf("CIDR 格式错误")
		}
		if !trusted && !g.ipAllowed(ipnet.IP) && !g.ipAllowed(widest(ipnet)) {
			return g.reject(t)
		}
		g.nets = append(g.nets, ipnet)
		return nil
	}
	if ip := net.ParseIP(t); ip != nil {
		if !trusted && !g.ipAllowed(ip) {
			return g.reject(t)
		}
		g.singles = append(g.singles, ip)
		return nil
	}
	if !validDomain(t) {
		return fmt.Errorf("不是合法的 IP/CIDR/域名")
	}
	d := strings.ToLower(t)
	if !trusted {
		// 请求里的域名：解析后所有 IP 都必须通过（私网模式查私网，公网模式查白名单网段）
		ips, err := net.LookupIP(d)
		if err != nil {
			return fmt.Errorf("域名 %s 解析失败：请求中的域名必须当前可解析", d)
		}
		for _, ip := range ips {
			if !g.ipAllowed(ip) {
				return g.reject(d)
			}
		}
	}
	g.domains = append(g.domains, d)
	return nil
}

// CheckIP 运行时逐 IP 校验。引擎发包前必须调用，false 则丢弃并记日志。
func (g *Guard) CheckIP(ip net.IP) bool { return g.ipAllowed(ip) }

// CheckHost 校验一个主机名/IP 字符串。IP 直接判；域名要求命中白名单域名
// 且解析出的所有 IP 都通过。
func (g *Guard) CheckHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(host); ip != nil {
		return g.ipAllowed(ip)
	}
	for _, d := range g.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true // 入列时已验证
		}
	}
	return false
}

func (g *Guard) ipAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if isPrivate(ip) {
		return true
	}
	if !g.allowPublic {
		return false
	}
	for _, n := range g.nets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, s := range g.singles {
		if s.Equal(ip) {
			return true
		}
	}
	return false
}

// isPrivate 判断是否属于允许的本地范围：
// RFC1918 私网、环回、链路本地。公网永远需要显式解锁且命中白名单。
func isPrivate(ip net.IP) bool {
	privateNets := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16",
	}
	for _, s := range privateNets {
		_, n, _ := net.ParseCIDR(s)
		if n.Contains(ip) {
			return true
		}
	}
	// IPv6 本地：::1 与 fc00::/7
	if ip.To4() == nil {
		if ip.Equal(net.ParseIP("::1")) {
			return true
		}
		if _, n, _ := net.ParseCIDR("fc00::/7"); n.Contains(ip) {
			return true
		}
	}
	return false
}

func (g *Guard) reject(t string) error {
	if !g.allowPublic {
		return fmt.Errorf("目标 %q 不在私网范围内。公网探测需在设置中解锁并加入白名单", t)
	}
	return fmt.Errorf("目标 %q 不在白名单内", t)
}

// Count 可用目标数量（网段算 1）
func (g *Guard) Count() int {
	return len(g.nets) + len(g.singles) + len(g.domains)
}

// TargetIPs 展开所有目标为待探测的 host 列表（域名保持原样，解析在引擎做）。
// 大网段不展开为逐 IP，返回 CIDR 由端口扫描阶段处理；首期 Web 探测
// 只支持单 IP 与域名，大网段留给二期 naabu。
func (g *Guard) TargetIPs() ([]string, error) {
	var out []string
	for _, s := range g.singles {
		out = append(out, s.String())
	}
	for _, d := range g.domains {
		out = append(out, d)
	}
	return out, nil
}

func validDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" || len(part) > 63 {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// widest 返回 CIDR 网段的起始 IP（用于网段归属的宽松判断）
func widest(n *net.IPNet) net.IP {
	return n.IP
}
