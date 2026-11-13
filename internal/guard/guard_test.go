package guard

import (
	"net"
	"testing"

	"dianbing/internal/model"
)

func privateSettings() model.Settings {
	return model.Settings{Whitelist: "", AllowPublic: false, MaxRate: 200}
}

func TestPrivateIPAllowed(t *testing.T) {
	g, err := New(privateSettings(), false)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.10", true},
		{"10.0.0.5", true},
		{"172.16.3.1", true},
		{"172.32.0.1", false}, // 172.16/12 之外，属公网
		{"127.0.0.1", true},
		{"8.8.8.8", false}, // 公网，未解锁
		{"169.254.1.1", true},
	}
	for _, c := range cases {
		if got := g.CheckIP(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("CheckIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestPublicRejectedWithoutUnlock(t *testing.T) {
	g, err := New(privateSettings(), false)
	if err != nil {
		t.Fatal(err)
	}
	err = g.AddTargets([]string{"8.8.8.8"})
	if err == nil {
		t.Fatal("公网目标在未解锁时应被拒绝")
	}
}

func TestPublicRequiresBothSwitches(t *testing.T) {
	// 设置里没解锁，请求里解锁 → 拒绝
	s := privateSettings()
	if _, err := New(s, true); err != nil {
		t.Fatal(err)
	}
	g, _ := New(s, true)
	if err := g.AddTargets([]string{"8.8.8.8"}); err == nil {
		t.Fatal("设置未解锁时，仅请求解锁不应生效")
	}

	// 设置解锁 + 请求解锁 → 白名单内的公网 IP 放行
	s.Whitelist = "8.8.8.0/24\n"
	s.AllowPublic = true
	g2, err := New(s, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := g2.AddTargets([]string{"8.8.8.8"}); err != nil {
		t.Fatalf("白名单内公网 IP 应放行: %v", err)
	}
	if !g2.CheckIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("8.8.8.8 应通过 CheckIP")
	}
	if g2.CheckIP(net.ParseIP("8.8.9.8")) {
		t.Fatal("8.8.9.8 不在 /24 内，应拒绝")
	}
}

func TestCIDROutsideWhitelistRejected(t *testing.T) {
	g, err := New(privateSettings(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.AddTargets([]string{"192.168.1.0/24"}); err != nil {
		t.Fatalf("私网 CIDR 应放行: %v", err)
	}
	if err := g.AddTargets([]string{"1.2.3.0/24"}); err == nil {
		t.Fatal("公网 CIDR 未解锁应拒绝")
	}
}

func TestInvalidTarget(t *testing.T) {
	g, _ := New(privateSettings(), false)
	if err := g.AddTargets([]string{"not a target!"}); err == nil {
		t.Fatal("非法目标应被拒绝")
	}
}
