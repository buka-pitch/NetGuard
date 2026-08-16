package ai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOllamaClient_Chat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/chat" {
			t.Errorf("expected /api/chat, got %s", r.URL.Path)
		}
		var req ollamaChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Model == "" {
			t.Error("expected model to be set")
		}
		if len(req.Messages) == 0 {
			t.Error("expected at least one message")
		}
		resp := ollamaChatResponse{
			Message: ollamaMessage{Role: "assistant", Content: "Here are the connections:\n1. curl → 1.1.1.1:80"},
			Done:    true,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := NewOllamaClient(srv.URL, "test-model")
	reply, err := c.Chat([]Message{
		{Role: "user", Content: "show me connections to 1.1.1.1"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Content == "" {
		t.Error("expected non-empty reply")
	}
}

func TestOllamaClient_ChatServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewOllamaClient(srv.URL, "test-model")
	_, err := c.Chat([]Message{
		{Role: "user", Content: "hello"},
	}, nil)
	if err == nil {
		t.Fatal("expected error for server error")
	}
}

func TestOllamaClient_ToolCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ollamaChatRequest
		json.NewDecoder(r.Body).Decode(&req)

		resp := ollamaChatResponse{
			Message: ollamaMessage{
				Role:    "assistant",
				Content: "",
				ToolCalls: []ollamaToolCall{{
					Type: "function",
					Function: ollamaToolCallFunc{
						Name: "query_connections",
						Arguments: json.RawMessage(`{"remote_ip":"1.1.1.1"}`),
					},
				}},
			},
			Done: true,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := NewOllamaClient(srv.URL, "test-model")
	reply, err := c.Chat([]Message{
		{Role: "user", Content: "show me connections to 1.1.1.1"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.ToolCalls) == 0 {
		t.Error("expected tool calls")
	}
}

func TestBuildSystemPrompt(t *testing.T) {
	prompt := buildSystemPrompt()
	if prompt == "" {
		t.Fatal("expected non-empty system prompt")
	}
}

func TestOllamaClient_ListModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Errorf("expected /api/tags, got %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"models": []map[string]interface{}{
				{"name": "qwen3:8b", "size": int64(4800000000)},
				{"name": "llama3.1:8b", "size": int64(4600000000)},
			},
		})
	}))
	defer srv.Close()

	c := NewOllamaClient(srv.URL, "test-model")
	models, err := c.ListModels()
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 2 {
		t.Fatalf("expected 2 models, got %d", len(models))
	}
	if models[0].Name != "qwen3:8b" {
		t.Errorf("expected qwen3:8b, got %s", models[0].Name)
	}
}

func TestOllamaClient_SelectModel(t *testing.T) {
	c := NewOllamaClient("http://localhost:11434", "qwen3:8b")
	if c.CurrentModel() != "qwen3:8b" {
		t.Errorf("expected qwen3:8b, got %s", c.CurrentModel())
	}
	c.SelectModel("llama3.1:8b")
	if c.CurrentModel() != "llama3.1:8b" {
		t.Errorf("expected llama3.1:8b, got %s", c.CurrentModel())
	}
}
