package server

import (
	"fmt"
	"mime"
	"net/smtp"
	"strconv"
	"strings"
)

func (s *Server) sendVerificationEmail(to, code, locale string) error {
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
	subjectText, body := verificationEmail(locale, code)
	subject := mime.QEncoding.Encode("UTF-8", subjectText)
	message := []byte("To: " + to + "\r\nFrom: " + from + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body)
	return smtp.SendMail(host+":"+port, auth, from, []string{to}, message)
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
