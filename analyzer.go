package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TrafficAnalyzer 流量分析器
type TrafficAnalyzer struct {
	connections  map[string]*ConnectionInfo
	httpRequests map[string]*HTTPRequestInfo
	mutex        sync.RWMutex
	stats        *AnalyzerStats
}

// ConnectionInfo 连接信息
type ConnectionInfo struct {
	ID            string
	ClientAddr    string
	TargetAddr    string
	StartTime     time.Time
	EndTime       time.Time
	BytesSent     int64
	BytesReceived int64
	IsHTTP        bool
	Duration      time.Duration
}

// HTTPRequestInfo HTTP请求信息
type HTTPRequestInfo struct {
	ID            string
	Method        string
	URL           string
	Host          string
	UserAgent     string
	ContentType   string
	ContentLength int64
	Headers       map[string]string
	QueryParams   map[string][]string
	Timestamp     time.Time
	ResponseCode  int
	ResponseTime  time.Duration
	Modified      bool
}

// AnalyzerStats 分析器统计信息
type AnalyzerStats struct {
	TotalConnections  int64
	HTTPConnections   int64
	HTTPSConnections  int64
	TotalDataTransfer int64
	UniqueHosts       map[string]int
	TopUserAgents     map[string]int
	RequestMethods    map[string]int
	ResponseCodes     map[string]int
	mutex             sync.RWMutex
}

// NewTrafficAnalyzer 创建新的流量分析器
func NewTrafficAnalyzer() *TrafficAnalyzer {
	return &TrafficAnalyzer{
		connections:  make(map[string]*ConnectionInfo),
		httpRequests: make(map[string]*HTTPRequestInfo),
		stats: &AnalyzerStats{
			UniqueHosts:    make(map[string]int),
			TopUserAgents:  make(map[string]int),
			RequestMethods: make(map[string]int),
			ResponseCodes:  make(map[string]int),
		},
	}
}

// RecordConnection 记录连接信息
func (ta *TrafficAnalyzer) RecordConnection(clientAddr, targetAddr string, isHTTP bool) string {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	connID := ta.generateID(clientAddr + targetAddr + time.Now().String())

	conn := &ConnectionInfo{
		ID:         connID,
		ClientAddr: clientAddr,
		TargetAddr: targetAddr,
		StartTime:  time.Now(),
		IsHTTP:     isHTTP,
	}

	ta.connections[connID] = conn

	// 更新统计信息
	ta.stats.mutex.Lock()
	ta.stats.TotalConnections++
	if isHTTP {
		ta.stats.HTTPConnections++
	} else {
		ta.stats.HTTPSConnections++
	}

	// 记录主机信息
	host := ta.extractHost(targetAddr)
	if host != "" {
		ta.stats.UniqueHosts[host]++
	}
	ta.stats.mutex.Unlock()

	log.Printf("记录连接: %s -> %s (HTTP: %v)", clientAddr, targetAddr, isHTTP)
	return connID
}

// RecordHTTPRequest 记录HTTP请求信息
func (ta *TrafficAnalyzer) RecordHTTPRequest(req *http.Request, modified bool) string {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	reqID := ta.generateID(req.URL.String() + req.UserAgent() + time.Now().String())

	// 解析查询参数
	queryParams := make(map[string][]string)
	if req.URL.RawQuery != "" {
		params, _ := url.ParseQuery(req.URL.RawQuery)
		maps.Copy(queryParams, params)
	}

	// 提取头部信息
	headers := make(map[string]string)
	for key, values := range req.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	requestURL := req.URL.String()
	if req.Host != "" {
		requestURL = fmt.Sprintf("http://%s%s", req.Host, req.URL.Path)
	}

	httpReq := &HTTPRequestInfo{
		ID:            reqID,
		Method:        req.Method,
		URL:           requestURL,
		Host:          req.Host,
		UserAgent:     req.UserAgent(),
		ContentType:   req.Header.Get("Content-Type"),
		ContentLength: req.ContentLength,
		Headers:       headers,
		QueryParams:   queryParams,
		Timestamp:     time.Now(),
		Modified:      modified,
	}

	ta.httpRequests[reqID] = httpReq

	// 更新统计信息
	ta.stats.mutex.Lock()
	ta.stats.RequestMethods[req.Method]++
	if req.UserAgent() != "" {
		ta.stats.TopUserAgents[req.UserAgent()]++
	}
	ta.stats.mutex.Unlock()

	// 打印详细分析
	ta.analyzeHTTPRequest(httpReq)

	return reqID
}

// UpdateConnectionStats 更新连接统计信息
func (ta *TrafficAnalyzer) UpdateConnectionStats(connID string, bytesSent, bytesReceived int64) {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	if conn, exists := ta.connections[connID]; exists {
		conn.BytesSent += bytesSent
		conn.BytesReceived += bytesReceived

		ta.stats.mutex.Lock()
		ta.stats.TotalDataTransfer += bytesSent + bytesReceived
		ta.stats.mutex.Unlock()
	}
}

// CloseConnection 关闭连接记录
func (ta *TrafficAnalyzer) CloseConnection(connID string) {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	if conn, exists := ta.connections[connID]; exists {
		conn.EndTime = time.Now()
		conn.Duration = conn.EndTime.Sub(conn.StartTime)

		log.Printf("连接关闭: %s, 持续时间: %v, 发送: %d bytes, 接收: %d bytes",
			connID, conn.Duration, conn.BytesSent, conn.BytesReceived)
	}
}

// analyzeHTTPRequest 分析HTTP请求
func (ta *TrafficAnalyzer) analyzeHTTPRequest(req *HTTPRequestInfo) {
	log.Printf("=== HTTP请求详细分析 ===")
	log.Printf("请求ID: %s", req.ID)
	log.Printf("时间戳: %s", req.Timestamp.Format("2006-01-02 15:04:05"))
	log.Printf("方法: %s", req.Method)
	log.Printf("URL: %s", req.URL)
	log.Printf("Host: %s", req.Host)
	log.Printf("User-Agent: %s", req.UserAgent)
	log.Printf("Content-Type: %s", req.ContentType)
	log.Printf("Content-Length: %d", req.ContentLength)
	log.Printf("是否被修改: %v", req.Modified)

	// 分析URL结构
	if parsedURL, err := url.Parse(req.URL); err == nil {
		log.Printf("URL分析:")
		log.Printf("  协议: %s", parsedURL.Scheme)
		log.Printf("  主机: %s", parsedURL.Host)
		log.Printf("  路径: %s", parsedURL.Path)
		if parsedURL.RawQuery != "" {
			log.Printf("  查询字符串: %s", parsedURL.RawQuery)
		}
		if parsedURL.Fragment != "" {
			log.Printf("  片段: %s", parsedURL.Fragment)
		}
	}

	// 分析查询参数
	if len(req.QueryParams) > 0 {
		log.Printf("查询参数分析:")
		for key, values := range req.QueryParams {
			for _, value := range values {
				log.Printf("  %s: %s", key, value)
				// 检查敏感参数
				if ta.isSensitiveParam(key) {
					log.Printf("    ⚠️  检测到敏感参数: %s", key)
				}
			}
		}
	}

	// 分析请求头
	log.Printf("请求头分析:")
	for key, value := range req.Headers {
		log.Printf("  %s: %s", key, value)

		// 检查特殊头部
		switch strings.ToLower(key) {
		case "referer":
			log.Printf("    📍 来源页面: %s", value)
		case "accept-language":
			log.Printf("    🌍 语言偏好: %s", value)
		case "accept-encoding":
			log.Printf("    🗜️  编码支持: %s", value)
		case "cookie":
			log.Printf("    🍪 Cookie信息: %s", ta.maskSensitiveData(value))
		case "authorization":
			log.Printf("    🔐 认证信息: %s", ta.maskSensitiveData(value))
		}
	}

	// 安全性分析
	ta.performSecurityAnalysis(req)

	log.Printf("========================")
}

// performSecurityAnalysis 执行安全性分析
func (ta *TrafficAnalyzer) performSecurityAnalysis(req *HTTPRequestInfo) {
	log.Printf("安全性分析:")

	// 检查SQL注入模式
	if ta.containsSQLInjection(req.URL) {
		log.Printf("  ⚠️  可能的SQL注入尝试")
	}

	// 检查XSS模式
	if ta.containsXSS(req.URL) {
		log.Printf("  ⚠️  可能的XSS攻击尝试")
	}

	// 检查路径遍历
	if ta.containsPathTraversal(req.URL) {
		log.Printf("  ⚠️  可能的路径遍历攻击")
	}

	// 检查异常User-Agent
	if ta.isSuspiciousUserAgent(req.UserAgent) {
		log.Printf("  ⚠️  可疑的User-Agent")
	}

	// 检查大量参数（可能的参数污染）
	if len(req.QueryParams) > 20 {
		log.Printf("  ⚠️  参数数量异常 (%d个)", len(req.QueryParams))
	}
}

// containsSQLInjection 检查SQL注入模式
func (ta *TrafficAnalyzer) containsSQLInjection(url string) bool {
	sqlPatterns := []string{
		"union", "select", "insert", "update", "delete", "drop",
		"'", "--", "/*", "*/", "xp_", "sp_", "exec", "execute",
	}

	lowerURL := strings.ToLower(url)
	for _, pattern := range sqlPatterns {
		if strings.Contains(lowerURL, pattern) {
			return true
		}
	}
	return false
}

// containsXSS 检查XSS模式
func (ta *TrafficAnalyzer) containsXSS(url string) bool {
	xssPatterns := []string{
		"<script", "</script>", "javascript:", "onload=", "onerror=",
		"alert(", "confirm(", "prompt(", "document.cookie",
	}

	lowerURL := strings.ToLower(url)
	for _, pattern := range xssPatterns {
		if strings.Contains(lowerURL, pattern) {
			return true
		}
	}
	return false
}

// containsPathTraversal 检查路径遍历
func (ta *TrafficAnalyzer) containsPathTraversal(url string) bool {
	traversalPatterns := []string{
		"../", "..\\", "....//", "....\\\\", "%2e%2e%2f", "%2e%2e%5c",
	}

	lowerURL := strings.ToLower(url)
	for _, pattern := range traversalPatterns {
		if strings.Contains(lowerURL, pattern) {
			return true
		}
	}
	return false
}

// isSuspiciousUserAgent 检查可疑User-Agent
func (ta *TrafficAnalyzer) isSuspiciousUserAgent(userAgent string) bool {
	suspiciousPatterns := []string{
		"sqlmap", "nikto", "nmap", "masscan", "nessus", "burp",
		"python-requests", "curl", "wget", "scanner", "bot",
	}

	lowerUA := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerUA, pattern) {
			return true
		}
	}
	return false
}

// isSensitiveParam 检查敏感参数
func (ta *TrafficAnalyzer) isSensitiveParam(param string) bool {
	sensitiveParams := []string{
		"password", "passwd", "pwd", "token", "key", "secret",
		"api_key", "apikey", "auth", "session", "sid", "ssn",
		"credit_card", "card", "cvv", "pin",
	}

	lowerParam := strings.ToLower(param)
	for _, sensitive := range sensitiveParams {
		if strings.Contains(lowerParam, sensitive) {
			return true
		}
	}
	return false
}

// maskSensitiveData 掩码敏感数据
func (ta *TrafficAnalyzer) maskSensitiveData(data string) string {
	if len(data) <= 8 {
		return "***"
	}
	return data[:4] + "***" + data[len(data)-4:]
}

// extractHost 从地址中提取主机名
func (ta *TrafficAnalyzer) extractHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// generateID 生成唯一ID
func (ta *TrafficAnalyzer) generateID(input string) string {
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:])[:8]
}

// GetDetailedStats 获取详细统计信息
func (ta *TrafficAnalyzer) GetDetailedStats() *AnalyzerStats {
	ta.stats.mutex.RLock()
	defer ta.stats.mutex.RUnlock()

	// 创建副本以避免并发问题
	stats := &AnalyzerStats{
		TotalConnections:  ta.stats.TotalConnections,
		HTTPConnections:   ta.stats.HTTPConnections,
		HTTPSConnections:  ta.stats.HTTPSConnections,
		TotalDataTransfer: ta.stats.TotalDataTransfer,
		UniqueHosts:       make(map[string]int),
		TopUserAgents:     make(map[string]int),
		RequestMethods:    make(map[string]int),
		ResponseCodes:     make(map[string]int),
	}

	maps.Copy(stats.UniqueHosts, ta.stats.UniqueHosts)
	maps.Copy(stats.TopUserAgents, ta.stats.TopUserAgents)
	maps.Copy(stats.RequestMethods, ta.stats.RequestMethods)
	maps.Copy(stats.ResponseCodes, ta.stats.ResponseCodes)

	return stats
}

// PrintDetailedReport 打印详细报告
func (ta *TrafficAnalyzer) PrintDetailedReport() {
	stats := ta.GetDetailedStats()

	log.Printf("=== 详细流量分析报告 ===")
	log.Printf("总连接数: %d", stats.TotalConnections)
	log.Printf("HTTP连接数: %d", stats.HTTPConnections)
	log.Printf("HTTPS连接数: %d", stats.HTTPSConnections)
	log.Printf("总数据传输: %d bytes (%.2f MB)", stats.TotalDataTransfer, float64(stats.TotalDataTransfer)/1024/1024)

	log.Printf("\n访问的主机 (前10个):")
	ta.printTopEntries(stats.UniqueHosts, 10)

	log.Printf("\nUser-Agent统计 (前5个):")
	ta.printTopEntries(stats.TopUserAgents, 5)

	log.Printf("\nHTTP方法统计:")
	ta.printTopEntries(stats.RequestMethods, -1)

	log.Printf("\n响应代码统计:")
	ta.printTopEntries(stats.ResponseCodes, -1)

	log.Printf("========================")
}

// printTopEntries 打印排名前N的条目
func (ta *TrafficAnalyzer) printTopEntries(entries map[string]int, limit int) {
	type entry struct {
		key   string
		count int
	}

	var sorted []entry
	for k, v := range entries {
		sorted = append(sorted, entry{k, v})
	}

	// 简单排序
	for i := range len(sorted) - 1 {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].count > sorted[i].count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	end := len(sorted)
	if limit > 0 && limit < end {
		end = limit
	}

	for i := range end {
		log.Printf("  %s: %d", sorted[i].key, sorted[i].count)
	}
}
