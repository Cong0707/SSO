package server

import (
	"fmt"
	"mime"
	"net/smtp"
	"strconv"
	"strings"
)

func (s *Server) sendVerificationEmail(to, code string) error {
	host := strings.TrimSpace(s.setting(settingSMTPHost, ""))
	port := strings.TrimSpace(s.setting(settingSMTPPort, "587"))
	from := strings.TrimSpace(s.setting(settingSMTPFrom, ""))
	username := strings.TrimSpace(s.setting(settingSMTPUsername, ""))
	password := s.setting(settingSMTPPassword, "")
	if host == "" || from == "" {
		return fmt.Errorf("邮件服务尚未配置")
	}
	if parsed, err := strconv.Atoi(port); err != nil || parsed < 1 || parsed > 65535 {
		return fmt.Errorf("SMTP 端口无效")
	}
	var auth smtp.Auth
	if username != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}
	subject := mime.QEncoding.Encode("UTF-8", "xem SSO 邮箱验证码")
	body := "你的邮箱验证码是：" + code + "\r\n\r\n验证码 10 分钟内有效。如果不是你本人操作，请忽略此邮件。"
	message := []byte("To: " + to + "\r\nFrom: " + from + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body)
	return smtp.SendMail(host+":"+port, auth, from, []string{to}, message)
}
