package swu

func (s *Session) reportProgress(stage string) {
	if s.cfg.OnProgress != nil {
		s.cfg.OnProgress(stage)
	}
}
