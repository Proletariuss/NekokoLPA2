package driver

import "net"

// Platform-neutral XFRM constants keep the userspace SWu package buildable on
// non-Linux systems. Linux converts these values to netlink's typed enums.
const (
	XFRMProtoESP      = 50
	XFRMModeTunnel    = 1
	XFRMEncapESPInUDP = 2
	XFRMSADirIn       = 1
	XFRMSADirOut      = 2
	XFRMDirIn         = 0
	XFRMDirOut        = 1
	XFRMDirForward    = 2
	NetworkFamilyIPv4 = 2
	NetworkFamilyIPv6 = 10
)

type XFRMSAConfig struct {
	Src, Dst      net.IP
	SPI           uint32
	Proto         int
	IsAEAD        bool
	AeadAlgoName  string
	AeadKey       []byte
	AeadICVLen    int
	CryptAlgoName string
	CryptKey      []byte
	AuthAlgoName  string
	AuthKey       []byte
	AuthTruncLen  int
	EncapType     int
	EncapSrcPort  int
	EncapDstPort  int
	Ifid          int
	Mode          int
	TimeLimitSoft uint64
	TimeLimitHard uint64
	ReplayWindow  int
	SADir         int
	ESN           bool
}

type XFRMSPConfig struct {
	Src, Dst  *net.IPNet
	Dir       int
	TmplSrc   net.IP
	TmplDst   net.IP
	TmplProto int
	TmplMode  int
	TmplSPI   int
	Ifid      int
}
