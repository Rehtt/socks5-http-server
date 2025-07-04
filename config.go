package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// Config 配置结构
type Config struct {
	Server ServerConfig `json:"server"`
	Rules  []RuleConfig `json:"rules"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port           int    `json:"port"`
	EnableHTTPS    bool   `json:"enable_https"`
	LogLevel       string `json:"log_level"`
	ReportInterval int    `json:"report_interval"`
}

// RuleConfig 规则配置
type RuleConfig struct {
	Name         string            `json:"name"`
	Pattern      string            `json:"pattern"`
	ResponseBody string            `json:"response_body"`
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	Enabled      bool              `json:"enabled"`
}

// ConfigManager 配置管理器
type ConfigManager struct {
	config *Config
	path   string
}

// NewConfigManager 创建配置管理器
func NewConfigManager(configPath string) *ConfigManager {
	return &ConfigManager{
		path: configPath,
	}
}

// LoadConfig 加载配置
func (cm *ConfigManager) LoadConfig() (*Config, error) {
	// 如果配置文件不存在，创建默认配置
	if _, err := os.Stat(cm.path); os.IsNotExist(err) {
		log.Printf("配置文件不存在，创建默认配置: %s", cm.path)
		return cm.CreateDefaultConfig()
	}

	// 读取配置文件
	data, err := os.ReadFile(cm.path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	cm.config = &config
	log.Printf("成功加载配置文件: %s", cm.path)
	return &config, nil
}

// CreateDefaultConfig 创建默认配置
func (cm *ConfigManager) CreateDefaultConfig() (*Config, error) {
	config := &Config{
		Server: ServerConfig{
			Port:           1080,
			EnableHTTPS:    false,
			LogLevel:       "info",
			ReportInterval: 30,
		},
		Rules: []RuleConfig{
			{
				Name:    "Google拦截",
				Pattern: `.*google\.com.*`,
				ResponseBody: `
					<html>
					<head><title>被拦截的页面</title></head>
					<body>
						<h1>此页面已被SOCKS5代理拦截</h1>
						<p>原始请求已被修改</p>
						<p>规则: Google拦截</p>
						<p>时间: {{.Time}}</p>
					</body>
					</html>
				`,
				StatusCode: 200,
				Headers: map[string]string{
					"X-Proxy-Modified": "true",
					"X-Proxy-Rule":     "Google拦截",
				},
				Enabled: true,
			},
			{
				Name:    "百度重定向",
				Pattern: `.*baidu\.com.*`,
				ResponseBody: `
					<html>
					<head><title>百度访问被重定向</title></head>
					<body>
						<h1>百度搜索请求被拦截</h1>
						<p>这是一个自定义的响应页面</p>
						<p>原始URL被规则匹配并修改</p>
						<p>规则: 百度重定向</p>
					</body>
					</html>
				`,
				StatusCode: 200,
				Headers: map[string]string{
					"X-Custom-Header": "Modified by SOCKS5 Proxy",
					"X-Proxy-Rule":    "百度重定向",
				},
				Enabled: true,
			},
			{
				Name:    "社交媒体拦截",
				Pattern: `.*(facebook|twitter|instagram|tiktok)\.com.*`,
				ResponseBody: `
					<html>
					<head><title>社交媒体访问被限制</title></head>
					<body>
						<h1>社交媒体访问被限制</h1>
						<p>根据策略，此类网站访问被限制</p>
						<p>如需访问，请联系管理员</p>
					</body>
					</html>
				`,
				StatusCode: 403,
				Headers: map[string]string{
					"X-Proxy-Blocked": "true",
					"X-Proxy-Rule":    "社交媒体拦截",
				},
				Enabled: false, // 默认禁用
			},
			{
				Name:         "广告拦截",
				Pattern:      `.*(ads|advertisement|banner|popup).*`,
				ResponseBody: ``,
				StatusCode:   204,
				Headers: map[string]string{
					"X-Proxy-Blocked": "true",
					"X-Proxy-Rule":    "广告拦截",
				},
				Enabled: true,
			},
		},
	}

	// 保存默认配置
	err := cm.SaveConfig(config)
	if err != nil {
		return nil, fmt.Errorf("保存默认配置失败: %v", err)
	}

	cm.config = config
	return config, nil
}

// SaveConfig 保存配置
func (cm *ConfigManager) SaveConfig(config *Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %v", err)
	}

	err = ioutil.WriteFile(cm.path, data, 0o644)
	if err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}

	log.Printf("配置已保存到: %s", cm.path)
	return nil
}

// GetConfig 获取配置
func (cm *ConfigManager) GetConfig() *Config {
	return cm.config
}

// AddRule 添加规则
func (cm *ConfigManager) AddRule(rule RuleConfig) error {
	if cm.config == nil {
		return fmt.Errorf("配置未加载")
	}

	cm.config.Rules = append(cm.config.Rules, rule)
	return cm.SaveConfig(cm.config)
}

// RemoveRule 删除规则
func (cm *ConfigManager) RemoveRule(name string) error {
	if cm.config == nil {
		return fmt.Errorf("配置未加载")
	}

	for i, rule := range cm.config.Rules {
		if rule.Name == name {
			cm.config.Rules = append(cm.config.Rules[:i], cm.config.Rules[i+1:]...)
			return cm.SaveConfig(cm.config)
		}
	}

	return fmt.Errorf("未找到规则: %s", name)
}

// EnableRule 启用规则
func (cm *ConfigManager) EnableRule(name string) error {
	if cm.config == nil {
		return fmt.Errorf("配置未加载")
	}

	for i, rule := range cm.config.Rules {
		if rule.Name == name {
			cm.config.Rules[i].Enabled = true
			return cm.SaveConfig(cm.config)
		}
	}

	return fmt.Errorf("未找到规则: %s", name)
}

// DisableRule 禁用规则
func (cm *ConfigManager) DisableRule(name string) error {
	if cm.config == nil {
		return fmt.Errorf("配置未加载")
	}

	for i, rule := range cm.config.Rules {
		if rule.Name == name {
			cm.config.Rules[i].Enabled = false
			return cm.SaveConfig(cm.config)
		}
	}

	return fmt.Errorf("未找到规则: %s", name)
}

// ListRules 列出所有规则
func (cm *ConfigManager) ListRules() []RuleConfig {
	if cm.config == nil {
		return nil
	}
	return cm.config.Rules
}

// GetEnabledRules 获取启用的规则
func (cm *ConfigManager) GetEnabledRules() []RuleConfig {
	if cm.config == nil {
		return nil
	}

	var enabledRules []RuleConfig
	for _, rule := range cm.config.Rules {
		if rule.Enabled {
			enabledRules = append(enabledRules, rule)
		}
	}
	return enabledRules
}

// PrintConfig 打印配置信息
func (cm *ConfigManager) PrintConfig() {
	if cm.config == nil {
		log.Printf("配置未加载")
		return
	}

	log.Printf("=== 配置信息 ===")
	log.Printf("服务器端口: %d", cm.config.Server.Port)
	log.Printf("启用HTTPS: %v", cm.config.Server.EnableHTTPS)
	log.Printf("日志级别: %s", cm.config.Server.LogLevel)
	log.Printf("报告间隔: %d秒", cm.config.Server.ReportInterval)

	log.Printf("\n规则列表:")
	for i, rule := range cm.config.Rules {
		status := "禁用"
		if rule.Enabled {
			status = "启用"
		}
		log.Printf("  %d. %s (%s)", i+1, rule.Name, status)
		log.Printf("     模式: %s", rule.Pattern)
		log.Printf("     状态码: %d", rule.StatusCode)
	}
	log.Printf("===============")
}
