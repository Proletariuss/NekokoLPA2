package swu

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func awaitRequest(t *testing.T, ch <-chan RequestResult) RequestResult {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(time.Second):
		t.Fatal("request did not complete")
		return RequestResult{}
	}
}

func TestWindowReturnsSendFailureImmediately(t *testing.T) {
	want := errors.New("network is unreachable")
	m := NewTaskManager(context.Background(), nil, 1, func([][]byte) error { return want })
	defer m.Stop()
	result := awaitRequest(t, m.EnqueueRequest(0, ikev2.IKE_SA_INIT, nil, nil))
	if !errors.Is(result.Err, want) {
		t.Fatalf("lost transport failure: %v", result.Err)
	}
}

func TestWindowReturnsRetransmitFailure(t *testing.T) {
	want := errors.New("socket closed")
	var sends atomic.Int32
	m := NewTaskManager(context.Background(), nil, 1, func([][]byte) error {
		if sends.Add(1) > 1 {
			return want
		}
		return nil
	})
	defer m.Stop()
	ch := m.EnqueueRequest(0, ikev2.IKE_SA_INIT, nil, nil)
	m.mu.Lock()
	m.pending[0].Deadline = time.Now().Add(-time.Second)
	m.mu.Unlock()
	m.checkTimeouts()
	if result := awaitRequest(t, ch); !errors.Is(result.Err, want) {
		t.Fatalf("lost retransmit failure: %v", result.Err)
	}
}

func TestWindowStopDrainsPendingAndQueuedAndRejectsNewWork(t *testing.T) {
	var sends atomic.Int32
	m := NewTaskManager(context.Background(), nil, 1, func([][]byte) error { sends.Add(1); return nil })
	a := m.EnqueueRequest(0, ikev2.IKE_SA_INIT, nil, nil)
	b := m.EnqueueRequest(1, ikev2.IKE_AUTH, nil, nil)
	m.Stop()
	c := m.EnqueueRequest(2, ikev2.IKE_AUTH, nil, nil)
	for _, ch := range []<-chan RequestResult{a, b, c} {
		if result := awaitRequest(t, ch); !errors.Is(result.Err, context.Canceled) {
			t.Fatalf("request survived stop: %v", result.Err)
		}
	}
	if sends.Load() != 1 {
		t.Fatalf("sent queued work after stop: %d", sends.Load())
	}
	m.Stop() // idempotent, including after cancellation has drained.
}

func TestWindowSuccessfulResponseReleasesQueuedRequest(t *testing.T) {
	m := NewTaskManager(context.Background(), nil, 1, func([][]byte) error { return nil })
	defer m.Stop()
	a := m.EnqueueRequest(0, ikev2.IKE_SA_INIT, nil, nil)
	b := m.EnqueueRequest(1, ikev2.IKE_AUTH, nil, nil)
	if !m.HandleResponse(0, []byte("init")) || !m.HandleResponse(1, []byte("auth")) {
		t.Fatal("response was not matched")
	}
	for i, ch := range []<-chan RequestResult{a, b} {
		result := awaitRequest(t, ch)
		if result.Err != nil || string(result.Data) != []string{"init", "auth"}[i] {
			t.Fatalf("unexpected response: %+v", result)
		}
	}
}
