package console

import (
	"testing"
	"time"
)

func TestBrokerPubSub(t *testing.T) {
	b := NewBroker()
	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	if b.ClientCount() != 1 {
		t.Fatalf("expected 1 client, got %d", b.ClientCount())
	}

	evt := Event{Type: EventPolicyUpdate, HTML: "<p>test</p>"}
	b.Publish(evt)

	select {
	case got := <-ch:
		if got.Type != EventPolicyUpdate {
			t.Errorf("expected type %s, got %s", EventPolicyUpdate, got.Type)
		}
		if got.HTML != "<p>test</p>" {
			t.Errorf("expected HTML '<p>test</p>', got %q", got.HTML)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestBrokerUnsubscribe(t *testing.T) {
	b := NewBroker()
	ch := b.Subscribe()

	if b.ClientCount() != 1 {
		t.Fatalf("expected 1 client, got %d", b.ClientCount())
	}

	b.Unsubscribe(ch)

	if b.ClientCount() != 0 {
		t.Fatalf("expected 0 clients after unsubscribe, got %d", b.ClientCount())
	}
}

func TestBrokerSlowClientDrop(t *testing.T) {
	b := NewBroker()
	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	// Fill the channel buffer (32 events).
	for i := 0; i < 40; i++ {
		b.Publish(Event{Type: EventReconcile, HTML: "<p>event</p>"})
	}

	// Should not panic or block.
	count := 0
	for {
		select {
		case <-ch:
			count++
		default:
			goto done
		}
	}
done:
	if count != 32 {
		t.Errorf("expected 32 buffered events, got %d", count)
	}
}

func TestParseTemplates(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates() error: %v", err)
	}

	// Check that key templates are defined.
	expectedTemplates := []string{
		"layout", "nav", "dashboard", "dashboard_content",
		"policies", "policies_content",
		"policy_detail", "policy_detail_content",
		"nodes", "nodes_content",
		"stats_cards", "policy_table", "policy_row",
		"daemon_table",
	}

	for _, name := range expectedTemplates {
		if tmpl.Lookup(name) == nil {
			t.Errorf("template %q not found", name)
		}
	}
}

func TestStaticFS(t *testing.T) {
	sub, err := staticFS()
	if err != nil {
		t.Fatalf("staticFS() error: %v", err)
	}

	// Verify htmx.min.js exists.
	f, err := sub.Open("htmx.min.js")
	if err != nil {
		t.Fatalf("expected htmx.min.js in static FS: %v", err)
	}
	f.Close()

	// Verify sse.js exists.
	f, err = sub.Open("sse.js")
	if err != nil {
		t.Fatalf("expected sse.js in static FS: %v", err)
	}
	f.Close()
}
