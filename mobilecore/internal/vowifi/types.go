// Package vowifi 提供 VoWiFi 功能的公共类型与接口定义。
//
// 各子包（ike / esp / netstack / ims / sms）通过此包中定义的接口交互，
// 避免循环依赖。主控逻辑在 cmd/proletarius-macos/reader_vowifi_api.go 中
// 组装各组件。
package vowifi

// SIMAuthProvider 抽象 SIM 卡鉴权能力（由 readerManager 实现）。
// IKE 客户端通过此接口在 EAP-AKA 交互中触发 USIM AKA 鉴权。
type SIMAuthProvider interface {
	// AuthenticateEAPAKA 对给定 RAND/AUTN 执行 EAP-AKA 鉴权。
	// 返回 RES/CK/IK（成功）或 AUTS（同步失败）。
	AuthenticateEAPAKA(rand, autn []byte) (res, ck, ik, auts []byte, err error)
}

// SIMInfo 包含从 SIM 卡读取的必要信息。
type SIMInfo struct {
	IMSI            string
	MSISDN          string
	MCC             string
	MNC             string
	ICCID           string
	PrivateIdentity string // ISIM IMPI（如 user@ims.mnc030.mcc234.3gppnetwork.org）
	PublicIdentity  string // ISIM IMPU（如 sip:+447xxx@ims.mnc030.mcc234.3gppnetwork.org）
	HomeDomain      string // IMS 域（如 ims.mnc030.mcc234.3gppnetwork.org）
	SMSC            string // SIM EF-SMSP service-centre address used as RP-DA
	SMSCTarget      string // operator-provided PSI, or tel:SMSC fallback
}

// TunnelConfig VoWiFi 隧道配置。
type TunnelConfig struct {
	// EPDGFQDN ePDG 服务器地址
	EPDGFQDN string
	// EPDGPort ePDG 端口（通常 4500 或 500）
	EPDGPort int
	// EPDGSource 记录地址来自自定义配置、运营商模板或 3GPP 标准推导。
	EPDGSource string
	// ProxyAddr 用户手动填写的 SOCKS5/HTTP 代理地址，空=直连
	ProxyAddr string
	// LocalIdentifier IKE Local ID（如 0$imsi@nai.epc.mnc033.mcc234.3gppnetwork.org）
	LocalIdentifier string
	// IMEI 设备 IMEI（用于 SIP UE 头）
	IMEI string
	// IMSDomain IMS 域（如 ims.mnc030.mcc234.3gppnetwork.org）
	IMSDomain string
	// IMSAuthAlgorithm IMS 摘要算法（"md5" 或 "akav1-md5"）
	IMSAuthAlgorithm string
	// UseIPSec 是否要求 IMS over IPsec
	UseIPSec bool
	// NATTKeepalive NAT 保活间隔（秒）
	NATTKeepalive int
	// IKE/Child SA 参数来自匹配后的运营商模板。
	IKEEncryption   string
	IKEIntegrity    string
	IKEPRF          string
	IKEDHGroup      int
	ChildEncryption string
	ChildIntegrity  string
	ChildDHGroup    int
	// DisableSwitchToNATTPort 仅用于少数明确要求保持 500 端口的模板。
	DisableSwitchToNATTPort bool
}

// TunnelResult 隧道建立结果。
type TunnelResult struct {
	// InnerIPv4 隧道内 IPv4 地址
	InnerIPv4 string
	// InnerIPv6 隧道内 IPv6 地址
	InnerIPv6 string
	// PCSCF P-CSCF 地址列表
	PCSCF []string
	// DNS 隧道内 DNS 服务器
	DNS []string
}

// IMSRegisterResult IMS 注册结果。
type IMSRegisterResult struct {
	Registered   bool
	MSISDN       string
	Transport    string // "udp" / "tcp" / "tls"
	SecurityMode string // "none" / "ipsec"
}
