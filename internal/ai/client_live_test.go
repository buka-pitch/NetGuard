//go:build live

package ai

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"netmon/internal/store"
)

func requireOllama(t *testing.T) {
	baseURL := os.Getenv("OLLAMA_URL")
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(baseURL)
	if err != nil {
		t.Fatalf("Ollama is not running at %s — start it with 'ollama serve' or set OLLAMA_URL: %v", baseURL, err)
	}
	resp.Body.Close()
}

func TestLiveOllama_Chat(t *testing.T) {
	requireOllama(t)

	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = "qwen3:8b"
	}

	c := NewOllamaClient("", model)
	t.Logf("connecting to Ollama with model=%q", model)
	reply, err := c.Chat([]Message{
		{Role: "user", Content: "reply with exactly one word: hello"},
	}, nil)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			t.Fatalf("model %q is not installed — run: ollama pull %s", model, model)
		}
		if strings.Contains(err.Error(), "subscription") || strings.Contains(err.Error(), "403") {
			t.Skipf("model %q requires a subscription — chat tests skipped", model)
		}
		t.Fatal("chat error:", err)
	}
	if reply.Content == "" {
		t.Fatal("expected non-empty reply")
	}
	t.Logf("reply: %q", reply.Content)
}

func TestLiveOllama_ListModels(t *testing.T) {
	requireOllama(t)

	c := NewOllamaClient("", "")
	models, err := c.ListModels()
	if err != nil {
		t.Fatal("list models error:", err)
	}
	if len(models) == 0 {
		t.Log("Ollama is running but no models are installed")
		t.Log("pull a model: ollama pull qwen3:8b")
		t.Fatal("zero models available — install at least one model to test chat functionality")
	}
	t.Logf("found %d models", len(models))
	for _, m := range models {
		t.Logf("  %s (%d MB)", m.Name, m.Size/1024/1024)
	}
}

func TestLiveOllama_SelectModel(t *testing.T) {
	requireOllama(t)

	c := NewOllamaClient("", "")
	models, err := c.ListModels()
	if err != nil {
		t.Fatal("list models error:", err)
	}
	if len(models) == 0 {
		t.Skip("skip: no models installed to select from")
	}

	first := models[0].Name
	err = c.SelectModel(first)
	if err != nil {
		t.Fatal("select model error:", err)
	}
	if c.CurrentModel() != first {
		t.Fatalf("expected %q, got %q", first, c.CurrentModel())
	}
	t.Logf("selected model: %s", first)
}

func TestLiveOllama_ToolCall(t *testing.T) {
	requireOllama(t)

	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = "qwen3:8b"
	}

	// Create a real store for the tool registry
	dbPath := fmt.Sprintf("/tmp/netmon_test_live_%d.db", time.Now().UnixNano())
	defer os.Remove(dbPath)

	st, err := store.New(dbPath, 100)
	if err != nil {
		t.Fatal("store error:", err)
	}
	defer st.Close()

	c := NewOllamaClient("", model)
	handler := NewChatHandler(c, st)

	reply, err := handler.Handle([]Message{
		{Role: "user", Content: "use the get_stats tool to show me the network statistics"},
	})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			t.Fatalf("model %q is not installed — run: ollama pull %s", model, model)
		}
		if strings.Contains(err.Error(), "subscription") || strings.Contains(err.Error(), "403") {
			t.Skipf("model %q requires a subscription — tool call tests skipped", model)
		}
		// Ollama may not support tool calling in all models
		if strings.Contains(err.Error(), "status 400") || strings.Contains(err.Error(), "not supported") {
			t.Skip("model may not support tool calls:", err)
		}
		t.Fatal("chat error:", err)
	}
	if reply == "" {
		t.Fatal("expected non-empty reply")
	}
	t.Logf("tool call reply: %s", reply[:min(len(reply), 200)])
}
