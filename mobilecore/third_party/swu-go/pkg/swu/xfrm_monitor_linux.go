//go:build linux

package swu

import (
	"github.com/1239t/swu-go/pkg/logger"
	"github.com/iniwex5/netlink"
	"github.com/iniwex5/netlink/nl"
)

func (s *Session) startXFRMExpireMonitor() {
	if s.xfrmMgr == nil {
		return
	}
	ch := make(chan netlink.XfrmMsg)
	done := make(chan struct{})
	errCh := make(chan error, 1)
	if err := netlink.XfrmMonitor(ch, done, errCh, nl.XFRM_MSG_EXPIRE); err != nil {
		s.Logger.Warn("启动 XFRM Expire 监听失败", logger.Err(err))
		return
	}
	go func() {
		defer close(done)
		for {
			select {
			case <-s.ctx.Done():
				return
			case err := <-errCh:
				s.Logger.Warn("XFRM 监听错误", logger.Err(err))
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				expire, ok := msg.(*netlink.XfrmMsgExpire)
				if !ok || expire.XfrmState == nil {
					continue
				}
				spi := uint32(expire.XfrmState.Spi)
				if (s.ChildSAOut == nil || s.ChildSAOut.SPI != spi) && (s.ChildSAIn == nil || s.ChildSAIn.SPI != spi) {
					continue
				}
				if expire.Hard {
					if s.OnSessionDown != nil {
						go s.OnSessionDown()
					} else if s.cancel != nil {
						s.cancel()
					}
				} else {
					go func() {
						if err := s.RekeyChildSA(); err != nil {
							s.Logger.Warn("Soft Expire 触发 Rekey 失败", logger.Err(err))
						}
					}()
				}
			}
		}
	}()
}
