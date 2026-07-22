package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type weChatProvider struct {
	config Config
}

func newWeChatProvider(config Config) (Provider, error) {
	if config.ClientID == "" || config.ClientSecret == "" || config.AuthorizationURL == "" || config.TokenURL == "" || config.UserInfoURL == "" {
		return nil, errors.New("incomplete WeChat provider configuration")
	}
	return &weChatProvider{config: config}, nil
}

func (p *weChatProvider) Kind() string { return p.config.Kind }

func (p *weChatProvider) AuthorizationURL(_ context.Context, request AuthorizationRequest) (string, error) {
	return p.config.AuthorizationURL + "?appid=" + url.QueryEscape(p.config.ClientID) + "&redirect_uri=" + url.QueryEscape(request.RedirectURL) + "&response_type=code&scope=snsapi_login&state=" + url.QueryEscape(request.State) + "#wechat_redirect", nil
}

func (p *weChatProvider) Exchange(ctx context.Context, request CallbackRequest) (Identity, error) {
	client := p.config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	tokenURL := p.config.TokenURL + "?appid=" + url.QueryEscape(p.config.ClientID) + "&secret=" + url.QueryEscape(p.config.ClientSecret) + "&code=" + url.QueryEscape(request.Code) + "&grant_type=authorization_code"
	tokenRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return Identity{}, err
	}
	tokenResponse, err := client.Do(tokenRequest)
	if err != nil {
		return Identity{}, err
	}
	defer tokenResponse.Body.Close()
	if tokenResponse.StatusCode < 200 || tokenResponse.StatusCode >= 300 {
		return Identity{}, fmt.Errorf("WeChat token status %d", tokenResponse.StatusCode)
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		OpenID       string `json:"openid"`
		ErrorCode    int    `json:"errcode"`
		ErrorMessage string `json:"errmsg"`
	}
	if err := json.NewDecoder(io.LimitReader(tokenResponse.Body, 1<<20)).Decode(&token); err != nil {
		return Identity{}, err
	}
	if token.AccessToken == "" || token.OpenID == "" {
		return Identity{}, fmt.Errorf("WeChat token error %d: %s", token.ErrorCode, token.ErrorMessage)
	}
	userinfoURL := p.config.UserInfoURL + "?access_token=" + url.QueryEscape(token.AccessToken) + "&openid=" + url.QueryEscape(token.OpenID) + "&lang=zh_CN"
	userinfoRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return Identity{}, err
	}
	userinfoResponse, err := client.Do(userinfoRequest)
	if err != nil {
		return Identity{}, err
	}
	defer userinfoResponse.Body.Close()
	if userinfoResponse.StatusCode < 200 || userinfoResponse.StatusCode >= 300 {
		return Identity{}, fmt.Errorf("WeChat userinfo status %d", userinfoResponse.StatusCode)
	}
	var userinfo struct {
		OpenID       string `json:"openid"`
		Nickname     string `json:"nickname"`
		HeadImageURL string `json:"headimgurl"`
		ErrorCode    int    `json:"errcode"`
		ErrorMessage string `json:"errmsg"`
	}
	if err := json.NewDecoder(io.LimitReader(userinfoResponse.Body, 1<<20)).Decode(&userinfo); err != nil {
		return Identity{}, err
	}
	if userinfo.OpenID == "" {
		return Identity{}, fmt.Errorf("WeChat userinfo error %d: %s", userinfo.ErrorCode, userinfo.ErrorMessage)
	}
	return Identity{Subject: userinfo.OpenID, Username: userinfo.Nickname, Name: userinfo.Nickname, AvatarURL: userinfo.HeadImageURL}, nil
}
