package ai

import "testing"

// 回归：Spring Boot 规则曾因 header(k,"") 对任意输入恒真，
// 导致所有资产都被打上 Spring Boot 标签
func TestNoFalsePositiveOnGenericInput(t *testing.T) {
	an := NewRuleAnalyzer()
	generic := ProbeInput{
		URL:     "https://10.19.50.52:443",
		Status:  200,
		Title:   "业务系统",
		Server:  "openresty",
		Headers: map[string]string{"server": "openresty", "content-type": "text/html"},
		BodySniff: `<html><head><title>业务系统</title></head><body>欢迎登录</body></html>`,
	}
	tags := an.Analyze(generic)
	for _, tag := range tags {
		switch tag {
		case "Spring Boot", "Tomcat", "Jenkins", "PHP", "MinIO", "WordPress", "Swagger":
			t.Errorf("普通页面被误判为 %s（tags=%v）", tag, tags)
		}
	}
}

// 大小写键：探测层存表用小写键，规则必须用小写键查
func TestHeaderKeysAreLowercase(t *testing.T) {
	an := NewRuleAnalyzer()
	cases := []struct {
		name string
		in   ProbeInput
		want string
	}{
		{"php", ProbeInput{Headers: map[string]string{"x-powered-by": "PHP/7.4"}}, "PHP"},
		{"jenkins", ProbeInput{Headers: map[string]string{"x-jenkins": "2.300"}}, "Jenkins"},
		{"springboot-header", ProbeInput{Headers: map[string]string{"x-application-context": "app:prod"}}, "Spring Boot"},
		{"springboot-body", ProbeInput{BodySniff: "<div>Whitelabel Error Page</div>"}, "Spring Boot"},
		{"nginx", ProbeInput{Server: "nginx/1.24", Headers: map[string]string{"server": "nginx/1.24"}}, "Nginx"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			found := false
			for _, tag := range an.Analyze(c.in) {
				if tag == c.want {
					found = true
				}
			}
			if !found {
				t.Errorf("期望命中 %s，实际 tags=%v", c.want, an.Analyze(c.in))
			}
		})
	}
}
