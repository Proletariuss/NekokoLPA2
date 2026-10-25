//go:build !linux

package driver

import (
	"fmt"
	"net"
)

type XFRMManager struct{}

func NewXFRMManager() *XFRMManager               { return &XFRMManager{} }
func (x *XFRMManager) FlushAll()                 {}
func (x *XFRMManager) FlushByIP(net.IP)          {}
func (x *XFRMManager) Cleanup()                  {}
func (x *XFRMManager) UndoFuncs() []func() error { return nil }

func xfrmUnavailable() error { return fmt.Errorf("Linux XFRM is unavailable on this platform") }

func (x *XFRMManager) AddXFRMInterface(string, uint32, int) error { return xfrmUnavailable() }
func (x *XFRMManager) DelXFRMInterface(string) error              { return nil }
func (x *XFRMManager) AddSA(XFRMSAConfig) error                   { return xfrmUnavailable() }
func (x *XFRMManager) DelSA(uint32, net.IP, net.IP, int) error    { return nil }
func (x *XFRMManager) GetSALastUsed(uint32, net.IP, net.IP, int) (uint64, error) {
	return 0, nil
}
func (x *XFRMManager) AddSP(XFRMSPConfig) error    { return xfrmUnavailable() }
func (x *XFRMManager) DelSP(XFRMSPConfig) error    { return nil }
func (x *XFRMManager) UpdateSA(XFRMSAConfig) error { return xfrmUnavailable() }
func (x *XFRMManager) UpdateSP(XFRMSPConfig) error { return xfrmUnavailable() }
