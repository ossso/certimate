package huaweicloud

import (
	"errors"
	"strings"
	"time"

	"github.com/certimate-go/certimate/pkg/core/certifier"
	"github.com/go-acme/lego/v4/challenge"
	hwc "github.com/go-acme/lego/v4/providers/dns/huaweicloud"
)

type ChallengerConfig struct {
	AccessKeyId           string `json:"accessKeyId"`
	SecretAccessKey       string `json:"secretAccessKey"`
	Region                string `json:"region"`
	DnsPropagationTimeout int    `json:"dnsPropagationTimeout,omitempty"`
	DnsTTL                int    `json:"dnsTTL,omitempty"`
}

// wrapperProvider 包装lego的huaweicloud provider，修复域名末尾点号的匹配问题
type wrapperProvider struct {
	provider challenge.Provider
}

func (w *wrapperProvider) Present(domain, token, keyAuth string) error {
	// 标准化域名，移除末尾的点号，避免匹配问题
	normalizedDomain := strings.TrimSuffix(domain, ".")
	return w.provider.Present(normalizedDomain, token, keyAuth)
}

func (w *wrapperProvider) CleanUp(domain, token, keyAuth string) error {
	// 标准化域名，移除末尾的点号，避免匹配问题
	normalizedDomain := strings.TrimSuffix(domain, ".")
	return w.provider.CleanUp(normalizedDomain, token, keyAuth)
}

func (w *wrapperProvider) Timeout() (timeout, interval time.Duration) {
	// 如果provider实现了ProviderTimeout接口，调用它的Timeout方法
	if timeoutProvider, ok := w.provider.(challenge.ProviderTimeout); ok {
		return timeoutProvider.Timeout()
	}
	// 否则返回默认值
	return 0, 0
}

func NewChallenger(config *ChallengerConfig) (certifier.ACMEChallenger, error) {
	if config == nil {
		return nil, errors.New("the configuration of the acme challenge provider is nil")
	}

	region := config.Region
	if region == "" {
		// 华为云的 SDK 要求必须传一个区域，实际上 DNS-01 流程里用不到，但不传会报错
		region = "cn-north-1"
	}

	providerConfig := hwc.NewDefaultConfig()
	providerConfig.AccessKeyID = config.AccessKeyId
	providerConfig.SecretAccessKey = config.SecretAccessKey
	providerConfig.Region = region
	if config.DnsPropagationTimeout != 0 {
		providerConfig.PropagationTimeout = time.Duration(config.DnsPropagationTimeout) * time.Second
	}
	if config.DnsTTL != 0 {
		providerConfig.TTL = int32(config.DnsTTL)
	}

	provider, err := hwc.NewDNSProviderConfig(providerConfig)
	if err != nil {
		return nil, err
	}

	// 返回包装后的provider，修复域名末尾点号的匹配问题
	return &wrapperProvider{provider: provider}, nil
}
