package mobilecore

func (e *Engine) ikeProgress(run *runningSession, stage string) {
	e.mu.Lock()
	attempt := e.attempt
	e.mu.Unlock()
	e.ikeProgressForAttempt(run, attempt, stage)
}

func (e *Engine) ikeProgressForAttempt(run *runningSession, attempt int, stage string) {
	e.mu.Lock()
	if e.run != run || run.ctx.Err() != nil || e.attempt != attempt || e.phase != "ike" || e.ikeStage == stage {
		e.mu.Unlock()
		return
	}
	e.ikeStage = stage
	e.mu.Unlock()
	e.host.OnEvent(e.Status())
}
