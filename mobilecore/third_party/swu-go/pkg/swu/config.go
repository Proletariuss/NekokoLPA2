package swu

import (
	"crypto/x509"
	"github.com/1239t/swu-go/pkg/sim"
)

type Config struct {
	EpDGAddr string
	EpDGPort uint16 // 默认 500
	APN      string
	// IPStack controls the address families requested from the ePDG and used
	// in the initial Child SA traffic selectors. Valid values are "ipv4",
	// "ipv6", and "ipv4v6". The empty value keeps the legacy dual-stack
	// behavior.
	IPStack   string
	LocalAddr string // 传出接口 IP (通常自动检测)
	DNSServer string // 可选: 用于解析 ePDG 域名的 DNS 服务器 (host:port)

	SIM          sim.SIMProvider
	EnableDriver bool // 是否创建 TUN 和路由 (需要 root)

	// 数据平面模式: "tun" (默认，用户空间 ESP) 或 "xfrmi" (内核 XFRM offload)
	DataplaneMode string
	// XFRMI 模式专用配置
	XFRMIfID uint32 // XFRM interface ID (默认自动分配)

	// 可选的特定配置
	MCC       string
	MNC       string
	LocalPort uint16 // 本地 UDP 端口 (默认 500)
	// IKELocalIdentifier overrides IKE_AUTH IDi only. EAP-AKA identity still
	// comes from the live SIM unless a valid fast-reauth context is present.
	IKELocalIdentifier string
	// ValidateRemoteCertificate requires certificate-based responder authentication
	// before EAP. False permits RFC 5998 EAP-only; it never skips a supplied AUTH.
	ValidateRemoteCertificate bool
	// RemoteIdentifier is the expected certificate DNS name/IP; empty uses EpDGAddr.
	RemoteIdentifier string
	// CertificateRoots optionally supplies explicit trust anchors. Nil uses the
	// platform trust store (including Apple's Security framework on iOS).
	CertificateRoots *x509.CertPool
	// CertificatePurpose is an explicit caller policy. Empty/"ike" preserves
	// RFC 4945 IKE EKUs; "server_auth" requires server-auth purpose throughout
	// the validated chain. It never bypasses trust or expected-hostname checks.
	CertificatePurpose string
	// ResponderIDrAliases are exact caller-authorized FQDN protocol identities
	// for a peer whose certificate still matches RemoteIdentifier. No aliases
	// are inferred from a peer, DNS, or certificate. AUTH binds the received IDr.
	ResponderIDrAliases []string
	// CertificateIntermediates supplies untrusted local DER CA candidates for
	// chain building. These never become trust anchors; nil keeps old behavior.
	CertificateIntermediates [][]byte
	// EAPIdentity overrides the permanent EAP-AKA identity used for both the
	// wire identity and key derivation; empty retains the SIM-derived NAI.
	EAPIdentity string
	// RequireFullEAP disables ticket and fast-reauth paths when a carrier's
	// initial IMS authorization needs fresh RES/RAND/AUTN from this session.
	RequireFullEAP    bool
	CookiePayloadType string
	CPInFinalAuth     bool
	RekeyPFS          int
	// DisableSwitchToNATTPort is required by a small number of carrier
	// profiles (notably Verizon) that keep ESP-in-UDP on the negotiated port.
	DisableSwitchToNATTPort bool
	// IKE SA 重认证间隔（秒），0 表示禁用
	// 默认 0 (不主动重认证，仅 Rekey)
	ReauthInterval       int
	IKELifetimeSeconds   int
	ChildLifetimeSeconds int
	// NATTKeepaliveSeconds controls ESP-in-UDP NAT mapping keepalive. Zero
	// uses the interoperable 20 second default.
	NATTKeepaliveSeconds int
	// DPDIntervalSeconds controls idle IKE Dead Peer Detection. Zero uses the
	// 120 second default. DPD starts only after the Child SA is ready.
	DPDIntervalSeconds int
	// DisableDPD suppresses active IKE DPD probes for carrier profiles that
	// explicitly disable them. Passive inbound liveness tracking remains on.
	DisableDPD bool

	TUNName string // TUN 设备名 (默认自动分配)
	TUNMTU  int    // TUN MTU，0 表示使用默认值（默认 1358，已预留约 142B 的 ESP-in-UDP 封装开销）

	// XFRM SA 抗重放窗口大小（0 = 使用默认值 32）
	// 高延迟/乱序网络建议设为 128 或 256
	ReplayWindow int

	// 启用 ESN（Extended Sequence Numbers, RFC 4303 §2.2.1）
	// 64 位序列号，防止高速网络下 32 位 SN 溢出
	// 默认 false（VoWiFi 场景通常不需要）
	EnableESN bool

	// DisableEAPMACValidation is retained for source compatibility only.
	// EAP-AKA/AKA' MAC verification is mandatory and this value is ignored.
	DisableEAPMACValidation bool
	// DeviceIdentityEnabled gates the optional 3GPP DEVICE_IDENTITY notify.
	// nil preserves the historical behavior (enabled when the SIM provider
	// supplies an IMEI); false disables both identity notify variants.
	DeviceIdentityEnabled *bool
	// AKAChallengeMode accepts "minimal" or "omit"; empty defaults to "minimal".
	// Both omit the optional classic EAP-AKA AT_CHECKCODE extension. Legacy
	// "checkcode" and "recompute" modes are unsupported and rejected before
	// opening the transport, not silently downgraded. Mandatory AT_MAC and
	// final IKE AUTH verification are unaffected. AKA' uses its own checkcode.
	AKAChallengeMode string

	EnableWiresharkKeyLog bool
	WiresharkKeyLogPath   string

	// RFC 5723: Session Resumption 跨会话凭证漂流保护
	ResumeTicket   []byte
	ResumeOldSKd   []byte
	OnTicketUpdate func(ticket, skd []byte)

	// RFC 4187: EAP-AKA Fast Re-authentication 跨会话快速重连
	// 从 ePDG 鉴权成功后提取的假名 ID 和密钥材料，用于下次断线重连时
	// 绕过物理 SIM 卡读取（AT+CSIM），实现 0-RTT 的极速软鉴权
	FastReauthID       string                                        // 来自 AT_NEXT_REAUTH_ID 的临时假名
	FastReauthMK       []byte                                        // Master Key (上次全量认证派生)
	FastReauthKAut     []byte                                        // K_Aut (用于 MAC 校验)
	FastReauthKEncr    []byte                                        // K_Encr (用于属性加密)
	OnFastReauthUpdate func(reauthID string, mk, kAut, kEncr []byte) // 外层持久化回调

	TransportFactory func(local string, remote string) (Transport, error)
	TUNFactory       func(name string) (TUN, error)
	NetTools         NetTools

	// OnReady is invoked once the Child SA dataplane is ready for inner traffic.
	OnReady func()
	// OnProgress reports fixed stage names only, never SIM identities or keys.
	OnProgress func(string)
	// OnAuthDiagnostic reports bounded enum metadata after each parsed IKE_AUTH
	// response is checked. It is synchronous and suppressed after cancellation.
	OnAuthDiagnostic func(AuthDiagnostic)
	// OnAuthRequestDiagnostic reports bounded metadata from a serialized and
	// encrypted outbound IKE_AUTH before enqueue. "prepared" does not prove
	// network delivery. It is synchronous and suppressed after cancellation.
	OnAuthRequestDiagnostic func(AuthRequestDiagnostic)

	// 支持自定义的 IKEv2 和 ESP 协商组合列表。如果留空，将使用内置的大而全强兼容默认套件。
	// 示例：[]string{"aes256gcm16-prfsha384-ecp384", "aes128-sha256-modp2048"}
	IKEProposals []string
	ESPProposals []string
}
