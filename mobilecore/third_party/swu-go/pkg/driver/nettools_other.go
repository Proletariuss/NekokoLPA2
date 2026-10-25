//go:build !linux

package driver

import "fmt"

// NetTools is present so the portable netstack mode shares the same Config
// surface. Kernel interface/routing methods intentionally return unsupported.
type NetTools struct{}

type linkAttrs struct{ Index int }
type linkStub struct{}

func (l *linkStub) Attrs() *linkAttrs { return &linkAttrs{} }

func NewNetTools() *NetTools { return &NetTools{} }

func unsupportedNetworkDriver() error {
	return fmt.Errorf("kernel network driver is unavailable on this platform; use netstack mode")
}

func (n *NetTools) GetLink(string) (*linkStub, error)      { return nil, unsupportedNetworkDriver() }
func (n *NetTools) SetLinkUp(string) error                 { return unsupportedNetworkDriver() }
func (n *NetTools) SetLinkDown(string) error               { return unsupportedNetworkDriver() }
func (n *NetTools) DeleteLink(string) error                { return nil }
func (n *NetTools) SetMTU(string, int) error               { return unsupportedNetworkDriver() }
func (n *NetTools) AddAddress(string, string) error        { return unsupportedNetworkDriver() }
func (n *NetTools) DelAddress(string, string) error        { return nil }
func (n *NetTools) AddAddress6(string, string) error       { return unsupportedNetworkDriver() }
func (n *NetTools) DelAddress6(string, string) error       { return nil }
func (n *NetTools) AddRoute(string, string, string) error  { return unsupportedNetworkDriver() }
func (n *NetTools) DelRoute(string, string, string) error  { return nil }
func (n *NetTools) AddRoute6(string, string, string) error { return unsupportedNetworkDriver() }
func (n *NetTools) DelRoute6(string, string, string) error { return nil }
