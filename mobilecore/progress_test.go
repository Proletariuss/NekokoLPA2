package mobilecore

import (
	"context"
	"encoding/json"
	"testing"
)

func TestStartupProgressCannotReplaceNewGenerationOrReadyStatus(t *testing.T) {
	host := &fakeHost{events: make(chan string, 8)}
	engine := NewEngine(host)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &runningSession{ctx: ctx}
	engine.run, engine.phase = run, "ike"
	engine.ikeProgress(run, "ike_sa_init")
	var status map[string]any
	if err := json.Unmarshal([]byte(<-host.events), &status); err != nil {
		t.Fatal(err)
	}
	if status["ike_stage"] != "ike_sa_init" {
		t.Fatal(status)
	}
	engine.ikeProgress(&runningSession{ctx: ctx}, "eap_aka")
	engine.attempt = 2
	engine.ikeProgressForAttempt(run, 1, "eap_aka")
	engine.phase = "ready"
	engine.ikeProgress(run, "eap_aka")
	engine.phase = "ike"
	cancel()
	engine.ikeProgress(run, "eap_aka")
	if engine.ikeStage != "ike_sa_init" || len(host.events) != 0 {
		t.Fatal("stale progress modified active status")
	}
}
