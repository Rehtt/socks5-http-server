package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SOCKS5常量定义
const (
	SOCKS5_VERSION = 0x05
	NO_AUTH        = 0x00
	CMD_CONNECT    = 0x01
	ATYP_IPV4      = 0x01
	ATYP_DOMAIN    = 0x03
	ATYP_IPV6      = 0x04
	REP_SUCCESS    = 0x00
	REP_FAILURE    = 0x01
)

// HTTPRule 定义HTTP规则匹配和修改
type HTTPRule struct {
	URLPattern   *regexp.Regexp
	ResponseBody string
	StatusCode   int
	Headers      map[string]string
}

// SOCKS5Server 服务器结构
type SOCKS5Server struct {
	listener      net.Listener
	rules         []HTTPRule
	rulesMutex    sync.RWMutex
	stats         *Stats
	analyzer      *TrafficAnalyzer
	configManager *ConfigManager
}

// Stats 统计信息
type Stats struct {
	TotalConnections  int64
	HTTPRequests      int64
	ModifiedResponses int64
	mutex             sync.RWMutex
}

// NewSOCKS5Server 创建新的SOCKS5服务器
func NewSOCKS5Server(configPath string) *SOCKS5Server {
	return &SOCKS5Server{
		rules:         make([]HTTPRule, 0),
		stats:         &Stats{},
		analyzer:      NewTrafficAnalyzer(),
		configManager: NewConfigManager(configPath),
	}
}

// AddRule 添加HTTP规则
func (s *SOCKS5Server) AddRule(pattern string, responseBody string, statusCode int, headers map[string]string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	s.rulesMutex.Lock()
	defer s.rulesMutex.Unlock()

	rule := HTTPRule{
		URLPattern:   regex,
		ResponseBody: responseBody,
		StatusCode:   statusCode,
		Headers:      headers,
	}
	s.rules = append(s.rules, rule)
	return nil
}

// LoadRulesFromConfig 从配置加载规则
func (s *SOCKS5Server) LoadRulesFromConfig() error {
	config, err := s.configManager.LoadConfig()
	if err != nil {
		return fmt.Errorf("加载配置失败: %v", err)
	}

	s.rulesMutex.Lock()
	defer s.rulesMutex.Unlock()

	// 清空现有规则
	s.rules = make([]HTTPRule, 0)

	// 添加启用的规则
	for _, ruleConfig := range config.Rules {
		if ruleConfig.Enabled {
			regex, err := regexp.Compile(ruleConfig.Pattern)
			if err != nil {
				log.Printf("规则 %s 的正则表达式无效: %v", ruleConfig.Name, err)
				continue
			}

			rule := HTTPRule{
				URLPattern:   regex,
				ResponseBody: ruleConfig.ResponseBody,
				StatusCode:   ruleConfig.StatusCode,
				Headers:      ruleConfig.Headers,
			}
			s.rules = append(s.rules, rule)
			log.Printf("加载规则: %s", ruleConfig.Name)
		}
	}

	log.Printf("成功加载 %d 个规则", len(s.rules))
	return nil
}

// Listen 启动服务器监听
func (s *SOCKS5Server) Listen(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = listener

	log.Printf("SOCKS5服务器启动在 %s", addr)

	// 打印配置信息
	s.configManager.PrintConfig()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接错误: %v", err)
			continue
		}

		s.stats.mutex.Lock()
		s.stats.TotalConnections++
		s.stats.mutex.Unlock()

		go s.handleConnection(conn)
	}
}

// handleConnection 处理客户端连接
func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// SOCKS5握手
	if !s.handleHandshake(conn) {
		return
	}

	// 处理连接请求
	targetConn, targetAddr := s.handleRequest(conn)
	if targetConn == nil {
		return
	}
	defer targetConn.Close()

	// 记录连接到分析器
	clientAddr := conn.RemoteAddr().String()
	connID := s.analyzer.RecordConnection(clientAddr, targetAddr, false) // 先设为false，后面根据实际数据判断

	// 检查是否为HTTP流量并进行相应处理
	s.handleTraffic(conn, targetConn, connID)
}

// handleHandshake 处理SOCKS5握手
func (s *SOCKS5Server) handleHandshake(conn net.Conn) bool {
	// 读取客户端握手请求
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		log.Printf("读取握手请求失败: %v", err)
		return false
	}

	// 检查版本
	if buf[0] != SOCKS5_VERSION {
		log.Printf("不支持的SOCKS版本: %d", buf[0])
		return false
	}

	// 发送握手响应（无需认证）
	response := []byte{SOCKS5_VERSION, NO_AUTH}
	_, err = conn.Write(response)
	if err != nil {
		log.Printf("发送握手响应失败: %v", err)
		return false
	}

	return true
}

// handleRequest 处理连接请求
func (s *SOCKS5Server) handleRequest(conn net.Conn) (net.Conn, string) {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		log.Printf("读取连接请求失败: %v", err)
		return nil, ""
	}

	// 解析请求
	if buf[0] != SOCKS5_VERSION || buf[1] != CMD_CONNECT {
		log.Printf("不支持的命令: %d", buf[1])
		s.sendResponse(conn, REP_FAILURE)
		return nil, ""
	}

	var targetAddr string

	// 解析目标地址
	switch buf[3] {
	case ATYP_IPV4:
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7], int(buf[8])<<8|int(buf[9]))
	case ATYP_DOMAIN:
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			log.Printf("域名长度不足")
			s.sendResponse(conn, REP_FAILURE)
			return nil, ""
		}
		domain := string(buf[5 : 5+domainLen])
		port := int(buf[5+domainLen])<<8 | int(buf[5+domainLen+1])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)

	default:
		log.Printf("不支持的地址类型: %d", buf[3])
		s.sendResponse(conn, REP_FAILURE)
		return nil, ""
	}

	// 连接目标服务器
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("连接目标服务器失败 %s: %v", targetAddr, err)
		s.sendResponse(conn, REP_FAILURE)
		return nil, ""
	}

	// 发送成功响应
	s.sendResponse(conn, REP_SUCCESS)

	log.Printf("成功建立连接到 %s", targetAddr)
	return targetConn, targetAddr
}

// sendResponse 发送SOCKS5响应
func (s *SOCKS5Server) sendResponse(conn net.Conn, rep byte) {
	response := []byte{
		SOCKS5_VERSION, rep, 0x00, ATYP_IPV4,
		0x00, 0x00, 0x00, 0x00, // IP地址
		0x00, 0x00, // 端口
	}
	conn.Write(response)
}

// isHTTPRequest 检查数据是否为HTTP请求
func (s *SOCKS5Server) isHTTPRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// 检查HTTP方法
	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE "}
	dataStr := string(data)

	for _, method := range httpMethods {
		if strings.HasPrefix(dataStr, method) {
			return true
		}
	}

	return false
}

// handleTraffic 处理流量，动态判断是否为HTTP
func (s *SOCKS5Server) handleTraffic(clientConn, targetConn net.Conn, connID string) {
	// 创建一个缓冲区来读取第一批数据
	firstBuffer := make([]byte, 1024)

	// 设置读取超时
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(firstBuffer)
	clientConn.SetReadDeadline(time.Time{}) // 清除超时

	if err != nil {
		log.Printf("读取首批数据失败: %v", err)
		s.relayTraffic(clientConn, targetConn)
		return
	}

	firstData := firstBuffer[:n]
	isHTTP := s.isHTTPRequest(firstData)

	// 更新分析器中的连接信息
	if conn, exists := s.analyzer.connections[connID]; exists {
		s.analyzer.mutex.Lock()
		conn.IsHTTP = isHTTP
		s.analyzer.mutex.Unlock()

		// 更新统计信息
		s.analyzer.stats.mutex.Lock()
		if isHTTP {
			s.analyzer.stats.HTTPConnections++
		} else {
			s.analyzer.stats.HTTPSConnections++
		}
		s.analyzer.stats.mutex.Unlock()
	}

	log.Printf("连接 %s 检测为 HTTP: %v", connID, isHTTP)

	if isHTTP {
		// 处理HTTP流量，需要先将第一批数据写入目标连接
		s.handleHTTPTrafficWithFirstData(clientConn, targetConn, firstData)
	} else {
		// 处理非HTTP流量，需要先将第一批数据转发
		s.relayTrafficWithFirstData(clientConn, targetConn, firstData)
	}
}

// handleHTTPTrafficWithFirstData 处理HTTP流量（包含首批数据）
func (s *SOCKS5Server) handleHTTPTrafficWithFirstData(clientConn, targetConn net.Conn, firstData []byte) {
	// 创建一个组合读取器，先读取首批数据，然后读取后续数据
	combinedReader := io.MultiReader(bytes.NewReader(firstData), clientConn)
	clientReader := bufio.NewReader(combinedReader)

	// 处理第一个HTTP请求
	req, err := http.ReadRequest(clientReader)
	if err != nil {
		log.Printf("读取HTTP请求失败: %v", err)
		// 如果无法解析为HTTP，则按普通流量处理
		s.relayTrafficWithFirstData(clientConn, targetConn, firstData)
		return
	}

	s.stats.mutex.Lock()
	s.stats.HTTPRequests++
	s.stats.mutex.Unlock()

	requestURL := req.URL.String()
	if req.Host != "" {
		requestURL = fmt.Sprintf("http://%s%s", req.Host, req.URL.Path)
	}

	log.Printf("HTTP请求: %s %s", req.Method, requestURL)

	// 检查是否匹配规则
	matched, rule := s.matchRule(requestURL)
	if matched {
		log.Printf("匹配规则，修改响应: %s", requestURL)

		// 记录到分析器（标记为已修改）
		s.analyzer.RecordHTTPRequest(req, true)

		s.sendModifiedResponse(clientConn, rule)

		s.stats.mutex.Lock()
		s.stats.ModifiedResponses++
		s.stats.mutex.Unlock()
		return
	}

	// 记录到分析器（未修改）
	s.analyzer.RecordHTTPRequest(req, false)

	// 转发请求到目标服务器
	err = req.Write(targetConn)
	if err != nil {
		log.Printf("转发请求失败: %v", err)
		return
	}

	// 读取并转发响应
	targetReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(targetReader, req)
	if err != nil {
		log.Printf("读取响应失败: %v", err)
		return
	}

	// 转发响应到客户端
	err = resp.Write(clientConn)
	if err != nil {
		log.Printf("转发响应失败: %v", err)
		return
	}

	// 继续处理后续的HTTP请求
	s.handleHTTPTraffic(clientConn, targetConn)
}

// relayTrafficWithFirstData 转发流量（包含首批数据）
func (s *SOCKS5Server) relayTrafficWithFirstData(clientConn, targetConn net.Conn, firstData []byte) {
	// 先发送第一批数据
	_, err := targetConn.Write(firstData)
	if err != nil {
		log.Printf("转发首批数据失败: %v", err)
		return
	}

	// 然后继续正常的流量转发
	s.relayTraffic(clientConn, targetConn)
}

// handleHTTPTraffic 处理HTTP流量
func (s *SOCKS5Server) handleHTTPTraffic(clientConn, targetConn net.Conn) {
	// 创建缓冲区来读取HTTP请求
	clientReader := bufio.NewReader(clientConn)

	for {
		// 读取HTTP请求
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				log.Printf("读取HTTP请求失败: %v", err)
			}
			break
		}

		s.stats.mutex.Lock()
		s.stats.HTTPRequests++
		s.stats.mutex.Unlock()

		requestURL := req.URL.String()
		if req.Host != "" {
			requestURL = fmt.Sprintf("http://%s%s", req.Host, req.URL.Path)
		}

		log.Printf("HTTP请求: %s %s", req.Method, requestURL)

		// 检查是否匹配规则
		matched, rule := s.matchRule(requestURL)
		if matched {
			log.Printf("匹配规则，修改响应: %s", requestURL)

			// 记录到分析器（标记为已修改）
			s.analyzer.RecordHTTPRequest(req, true)

			s.sendModifiedResponse(clientConn, rule)

			s.stats.mutex.Lock()
			s.stats.ModifiedResponses++
			s.stats.mutex.Unlock()
			continue
		}

		// 记录到分析器（未修改）
		s.analyzer.RecordHTTPRequest(req, false)

		// 转发请求到目标服务器
		err = req.Write(targetConn)
		if err != nil {
			log.Printf("转发请求失败: %v", err)
			break
		}

		// 读取并转发响应
		targetReader := bufio.NewReader(targetConn)
		resp, err := http.ReadResponse(targetReader, req)
		if err != nil {
			log.Printf("读取响应失败: %v", err)
			break
		}

		// 转发响应到客户端
		err = resp.Write(clientConn)
		if err != nil {
			log.Printf("转发响应失败: %v", err)
			break
		}
	}
}

// matchRule 检查URL是否匹配规则
func (s *SOCKS5Server) matchRule(requestURL string) (bool, HTTPRule) {
	s.rulesMutex.RLock()
	defer s.rulesMutex.RUnlock()

	for _, rule := range s.rules {
		if rule.URLPattern.MatchString(requestURL) {
			return true, rule
		}
	}
	return false, HTTPRule{}
}

// sendModifiedResponse 发送修改后的响应
func (s *SOCKS5Server) sendModifiedResponse(conn net.Conn, rule HTTPRule) {
	statusCode := rule.StatusCode
	if statusCode == 0 {
		statusCode = 200
	}

	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	response += "Content-Type: text/html; charset=utf-8\r\n"
	response += fmt.Sprintf("Content-Length: %d\r\n", len(rule.ResponseBody))

	// 添加自定义头部
	for key, value := range rule.Headers {
		response += fmt.Sprintf("%s: %s\r\n", key, value)
	}

	response += "\r\n" + rule.ResponseBody

	conn.Write([]byte(response))
}

// relayTraffic 转发非HTTP流量
func (s *SOCKS5Server) relayTraffic(clientConn, targetConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端到目标服务器
	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		targetConn.Close()
	}()

	// 目标服务器到客户端
	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		clientConn.Close()
	}()

	wg.Wait()
}

// GetStats 获取统计信息
func (s *SOCKS5Server) GetStats() Stats {
	s.stats.mutex.RLock()
	defer s.stats.mutex.RUnlock()
	return *s.stats
}

// analyzeHTTPRequest 分析HTTP请求
func analyzeHTTPRequest(req *http.Request) {
	log.Printf("=== HTTP请求分析 ===")
	log.Printf("方法: %s", req.Method)
	log.Printf("URL: %s", req.URL.String())
	log.Printf("Host: %s", req.Host)
	log.Printf("User-Agent: %s", req.UserAgent())

	// 分析查询参数
	if req.URL.RawQuery != "" {
		params, _ := url.ParseQuery(req.URL.RawQuery)
		log.Printf("查询参数:")
		for key, values := range params {
			for _, value := range values {
				log.Printf("  %s: %s", key, value)
			}
		}
	}

	// 分析请求头
	log.Printf("请求头:")
	for key, values := range req.Header {
		for _, value := range values {
			log.Printf("  %s: %s", key, value)
		}
	}
	log.Printf("==================")
}

func main() {
	server := NewSOCKS5Server("config.json")

	// 从配置文件加载规则
	err := server.LoadRulesFromConfig()
	if err != nil {
		log.Fatalf("加载规则失败: %v", err)
	}

	// 启动统计信息打印协程
	go func() {
		config := server.configManager.GetConfig()
		interval := 30 * time.Second
		if config != nil {
			interval = time.Duration(config.Server.ReportInterval) * time.Second
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			stats := server.GetStats()
			log.Printf("=== 基本统计信息 ===")
			log.Printf("总连接数: %d", stats.TotalConnections)
			log.Printf("HTTP请求数: %d", stats.HTTPRequests)
			log.Printf("修改响应数: %d", stats.ModifiedResponses)
			log.Printf("==================")

			// 打印详细分析报告
			server.analyzer.PrintDetailedReport()
		}
	}()

	// 启动服务器
	config := server.configManager.GetConfig()
	port := ":1080"
	if config != nil {
		port = fmt.Sprintf(":%d", config.Server.Port)
	}

	err = server.Listen(port)
	if err != nil {
		log.Fatalf("启动服务器失败: %v", err)
	}
}
