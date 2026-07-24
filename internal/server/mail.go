package server

import (
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

const (
	smtpDialTimeout = 15 * time.Second
	smtpIOTimeout   = 30 * time.Second
)

type smtpConnectionConfig struct {
	Host        string
	Port        string
	Username    string
	Password    string
	ImplicitTLS bool
	TLSConfig   *tls.Config
}

func (s *Server) sendVerificationEmail(to, code, locale string) error {
	subject, body := verificationEmail(locale, code)
	return s.sendEmail(to, subject, body)
}

func (s *Server) sendPasswordResetEmail(to, code, locale string) error {
	subject, body := passwordResetEmail(locale, code)
	return s.sendEmail(to, subject, body)
}

func (s *Server) sendEmail(to, subjectText, body string) error {
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
	subject := mime.QEncoding.Encode("UTF-8", subjectText)
	message := []byte("To: " + to + "\r\nFrom: " + from + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body)
	return sendSMTPMessage(smtpConnectionConfig{
		Host:        host,
		Port:        port,
		Username:    username,
		Password:    password,
		ImplicitTLS: port == "465",
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
		},
	}, from, []string{to}, message)
}

func sendSMTPMessage(config smtpConnectionConfig, from string, recipients []string, message []byte) error {
	address := net.JoinHostPort(config.Host, config.Port)
	dialer := &net.Dialer{Timeout: smtpDialTimeout}
	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: config.Host}
	}

	var (
		connection net.Conn
		err        error
	)
	if config.ImplicitTLS {
		connection, err = tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	} else {
		connection, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		return fmt.Errorf("连接 SMTP 服务器失败: %w", err)
	}
	if err := connection.SetDeadline(time.Now().Add(smtpIOTimeout)); err != nil {
		_ = connection.Close()
		return fmt.Errorf("设置 SMTP 超时失败: %w", err)
	}

	client, err := smtp.NewClient(connection, config.Host)
	if err != nil {
		_ = connection.Close()
		return fmt.Errorf("初始化 SMTP 客户端失败: %w", err)
	}
	defer client.Close()

	secure := config.ImplicitTLS
	if !secure {
		if supported, _ := client.Extension("STARTTLS"); supported {
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("SMTP STARTTLS 失败: %w", err)
			}
			secure = true
		}
	}
	if config.Username != "" {
		if !secure {
			return fmt.Errorf("SMTP 服务器未提供安全 TLS 连接，拒绝发送认证凭据")
		}
		if err := client.Auth(smtp.PlainAuth("", config.Username, config.Password, config.Host)); err != nil {
			return fmt.Errorf("SMTP 认证失败: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("设置 SMTP 发件人失败: %w", err)
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("设置 SMTP 收件人失败: %w", err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("开始写入 SMTP 邮件失败: %w", err)
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return fmt.Errorf("写入 SMTP 邮件失败: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("提交 SMTP 邮件失败: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("结束 SMTP 会话失败: %w", err)
	}
	return nil
}

func passwordResetEmail(locale, code string) (string, string) {
	switch requestLocale(locale, "") {
	case "fr":
		return "Réinitialisation du mot de passe xem SSO", "Votre code de réinitialisation est : " + code + "\r\n\r\nCe code expire dans 10 minutes. Ignorez cet e-mail si vous n'êtes pas à l'origine de cette demande."
	case "ru":
		return "Сброс пароля xem SSO", "Код сброса пароля: " + code + "\r\n\r\nКод действителен 10 минут. Если вы не отправляли этот запрос, проигнорируйте письмо."
	case "ja":
		return "xem SSO パスワードのリセット", "パスワードリセットコード: " + code + "\r\n\r\nこのコードは10分間有効です。心当たりがない場合は、このメールを無視してください。"
	case "vi":
		return "Đặt lại mật khẩu xem SSO", "Mã đặt lại mật khẩu của bạn là: " + code + "\r\n\r\nMã có hiệu lực trong 10 phút. Nếu bạn không yêu cầu, hãy bỏ qua email này."
	case "zhTW":
		return "重設 xem SSO 密碼", "你的密碼重設驗證碼是：" + code + "\r\n\r\n驗證碼於 10 分鐘內有效。如果不是你本人操作，請忽略此郵件。"
	case "zhCN":
		return "重置 xem SSO 密码", "你的密码重置验证码是：" + code + "\r\n\r\n验证码 10 分钟内有效。如果不是你本人操作，请忽略此邮件。"
	default:
		return "Reset your xem SSO password", "Your password reset code is: " + code + "\r\n\r\nThe code expires in 10 minutes. Ignore this email if you did not make this request."
	}
}

func verificationEmail(locale, code string) (string, string) {
	switch requestLocale(locale, "") {
	case "fr":
		return "Code de vérification xem SSO", "Votre code de vérification est : " + code + "\r\n\r\nCe code expire dans 10 minutes. Ignorez cet e-mail si vous n'êtes pas à l'origine de cette demande."
	case "ru":
		return "Код подтверждения xem SSO", "Ваш код подтверждения: " + code + "\r\n\r\nКод действителен 10 минут. Если вы не отправляли этот запрос, проигнорируйте письмо."
	case "ja":
		return "xem SSO メール認証コード", "メール認証コード: " + code + "\r\n\r\nこのコードは10分間有効です。心当たりがない場合は、このメールを無視してください。"
	case "vi":
		return "Mã xác minh email xem SSO", "Mã xác minh email của bạn là: " + code + "\r\n\r\nMã có hiệu lực trong 10 phút. Nếu bạn không yêu cầu, hãy bỏ qua email này."
	case "zhTW":
		return "xem SSO 電子郵件驗證碼", "你的電子郵件驗證碼是：" + code + "\r\n\r\n驗證碼於 10 分鐘內有效。如果不是你本人操作，請忽略此郵件。"
	case "zhCN":
		return "xem SSO 邮箱验证码", "你的邮箱验证码是：" + code + "\r\n\r\n验证码 10 分钟内有效。如果不是你本人操作，请忽略此邮件。"
	default:
		return "xem SSO email verification code", "Your email verification code is: " + code + "\r\n\r\nThe code expires in 10 minutes. Ignore this email if you did not make this request."
	}
}
