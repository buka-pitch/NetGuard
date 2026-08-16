package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type LLMClient interface {
	Chat(messages []Message, tools []ToolDef) (*LLMResponse, error)
	ChatStream(messages []Message, tools []ToolDef, onToken func(string)) error
	ListModels() ([]ModelInfo, error)
	CurrentModel() string
	SelectModel(name string) error
}

type ModelInfo struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type LLMResponse struct {
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

type Message struct {
	Role       string          `json:"role"`
	Content    string          `json:"content"`
	ToolCalls  []ToolCall      `json:"tool_calls,omitempty"`
	ToolResult string          `json:"tool_result,omitempty"`
}

type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type OllamaClient struct {
	baseURL string
	model   string
	http    *http.Client
}

func NewOllamaClient(baseURL, model string) *OllamaClient {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if model == "" {
		model = "qwen3:8b"
	}
	return &OllamaClient{
		baseURL: baseURL,
		model:   model,
		http:    &http.Client{Timeout: 120 * time.Second},
	}
}

func (c *OllamaClient) CurrentModel() string { return c.model }

func (c *OllamaClient) SelectModel(name string) error {
	c.model = name
	return nil
}

type ollamaTagsResponse struct {
	Models []struct {
		Name       string `json:"name"`
		Size       int64  `json:"size"`
	} `json:"models"`
}

func (c *OllamaClient) ListModels() ([]ModelInfo, error) {
	resp, err := c.http.Get(c.baseURL + "/api/tags")
	if err != nil {
		return nil, fmt.Errorf("ollama tags: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama tags status %d", resp.StatusCode)
	}
	var tr ollamaTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("decode tags: %w", err)
	}
	var models []ModelInfo
	for _, m := range tr.Models {
		models = append(models, ModelInfo{Name: m.Name, Size: m.Size})
	}
	return models, nil
}

type ollamaMessage struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	ToolCalls []ollamaToolCall `json:"tool_calls,omitempty"`
}

type ollamaToolCall struct {
	ID       string             `json:"id,omitempty"`
	Type     string             `json:"type"`
	Function ollamaToolCallFunc `json:"function"`
}

type ollamaToolCallFunc struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type ollamaToolDef struct {
	Type     string          `json:"type"`
	Function json.RawMessage `json:"function"`
}

type ollamaChatRequest struct {
	Model     string           `json:"model"`
	Messages  []ollamaMessage  `json:"messages"`
	Tools     []ollamaToolDef  `json:"tools,omitempty"`
	Stream    bool             `json:"stream"`
}

type ollamaChatResponse struct {
	Message ollamaMessage `json:"message"`
	Done    bool          `json:"done"`
}

func (c *OllamaClient) Chat(messages []Message, tools []ToolDef) (*LLMResponse, error) {
	var omsgs []ollamaMessage
	for _, m := range messages {
		om := ollamaMessage{Role: m.Role, Content: m.Content}
		if len(m.ToolCalls) > 0 {
			for _, tc := range m.ToolCalls {
				om.ToolCalls = append(om.ToolCalls, ollamaToolCall{
					ID:   tc.ID,
					Type: tc.Type,
					Function: ollamaToolCallFunc{
						Name:      tc.Function.Name,
						Arguments: tc.Function.Arguments,
					},
				})
			}
		}
		if m.Role == "tool" {
			om.Content = m.ToolResult
		}
		omsgs = append(omsgs, om)
	}

	var otools []ollamaToolDef
	for _, t := range tools {
		fn := fmt.Sprintf(`{"name":%q,"description":%q,"parameters":%s}`, t.Name, t.Description, string(t.Parameters))
		otools = append(otools, ollamaToolDef{
			Type:     "function",
			Function: json.RawMessage(fn),
		})
	}

	req := ollamaChatRequest{
		Model:    c.model,
		Messages: omsgs,
		Tools:    otools,
		Stream:   false,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.http.Post(c.baseURL+"/api/chat", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama status %d: %s", resp.StatusCode, string(respBody))
	}

	var oresp ollamaChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&oresp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	lr := &LLMResponse{Content: oresp.Message.Content}
	for _, tc := range oresp.Message.ToolCalls {
		lr.ToolCalls = append(lr.ToolCalls, ToolCall{
			ID:   tc.ID,
			Type: tc.Type,
			Function: struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}{
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
			},
		})
	}
	return lr, nil
}

func (c *OllamaClient) ChatStream(messages []Message, tools []ToolDef, onToken func(string)) error {
	var omsgs []ollamaMessage
	for _, m := range messages {
		om := ollamaMessage{Role: m.Role, Content: m.Content}
		if len(m.ToolCalls) > 0 {
			for _, tc := range m.ToolCalls {
				om.ToolCalls = append(om.ToolCalls, ollamaToolCall{
					ID:   tc.ID,
					Type: tc.Type,
					Function: ollamaToolCallFunc{
						Name:      tc.Function.Name,
						Arguments: tc.Function.Arguments,
					},
				})
			}
		}
		if m.Role == "tool" {
			om.Content = m.ToolResult
		}
		omsgs = append(omsgs, om)
	}

	var otools []ollamaToolDef
	for _, t := range tools {
		fn := fmt.Sprintf(`{"name":%q,"description":%q,"parameters":%s}`, t.Name, t.Description, string(t.Parameters))
		otools = append(otools, ollamaToolDef{
			Type:     "function",
			Function: json.RawMessage(fn),
		})
	}

	req := ollamaChatRequest{
		Model:    c.model,
		Messages: omsgs,
		Tools:    otools,
		Stream:   true,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal stream request: %w", err)
	}

	resp, err := c.http.Post(c.baseURL+"/api/chat", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("ollama stream request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ollama stream status %d: %s", resp.StatusCode, string(respBody))
	}

	dec := json.NewDecoder(resp.Body)
	for {
		var oresp ollamaChatResponse
		if err := dec.Decode(&oresp); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("decode stream response: %w", err)
		}
		if oresp.Message.Content != "" {
			onToken(oresp.Message.Content)
		}
		if oresp.Done {
			return nil
		}
	}
}

func buildSystemPrompt() string {
	return `You are netmon, a network monitoring assistant. You have access to tools that query live network data.

Rules:
- Always use tools to get real data. Never make up connection information.
- Format responses clearly with bullet points or numbered lists when showing multiple items.
- If a connection seems unusual (unknown process, blocklisted IP, odd port), flag it.
- If no data matches the query, say so clearly.
- When analyzing a connection for security, consider: process reputation, IP reputation, historical behavior, alert history, and port/protocol appropriateness.
- Keep responses concise but informative.
- Current time is ` + time.Now().Format(time.RFC3339) + ``
}

type ChatHandler struct {
	client  LLMClient
	reg     *Registry
	prompt  string
}

func NewChatHandler(client LLMClient, store Store) *ChatHandler {
	return &ChatHandler{
		client: client,
		reg:    NewRegistry(store),
		prompt: buildSystemPrompt(),
	}
}

func NewChatHandlerWithPcap(client LLMClient, store Store, pcap PcapLister) *ChatHandler {
	return &ChatHandler{
		client: client,
		reg:    NewRegistryWithPcap(store, pcap),
		prompt: buildSystemPrompt(),
	}
}

func (h *ChatHandler) ListModels() ([]ModelInfo, error) { return h.client.ListModels() }
func (h *ChatHandler) CurrentModel() string             { return h.client.CurrentModel() }
func (h *ChatHandler) SelectModel(name string) error    { return h.client.SelectModel(name) }

func (h *ChatHandler) Handle(messages []Message) (string, error) {
	msgs := []Message{{Role: "system", Content: h.prompt}}
	msgs = append(msgs, messages...)
	return h.chat(msgs, 0)
}

func (h *ChatHandler) HandleStream(messages []Message, onToken func(string)) error {
	msgs := []Message{{Role: "system", Content: h.prompt}}
	msgs = append(msgs, messages...)
	return h.chatStream(msgs, 0, onToken)
}

func (h *ChatHandler) chat(msgs []Message, depth int) (string, error) {
	if depth > 5 {
		return "I've reached the maximum number of tool calls. Please refine your question.", nil
	}

	reply, err := h.client.Chat(msgs, h.reg.Definitions())
	if err != nil {
		return "", err
	}

	if len(reply.ToolCalls) > 0 {
		for _, tc := range reply.ToolCalls {
			result, err := h.reg.Dispatch(tc.Function.Name, tc.Function.Arguments)
			if err != nil {
				result = fmt.Sprintf("error executing %s: %v", tc.Function.Name, err)
			}
			msgs = append(msgs, Message{Role: "assistant", Content: reply.Content, ToolCalls: reply.ToolCalls})
			msgs = append(msgs, Message{Role: "tool", ToolResult: result})
		}
		return h.chat(msgs, depth+1)
	}

	return reply.Content, nil
}

func (h *ChatHandler) chatStream(msgs []Message, depth int, onToken func(string)) error {
	if depth > 5 {
		onToken("I've reached the maximum number of tool calls. Please refine your question.")
		return nil
	}

	reply, err := h.client.Chat(msgs, h.reg.Definitions())
	if err != nil {
		return err
	}

	if len(reply.ToolCalls) > 0 {
		for _, tc := range reply.ToolCalls {
			result, err := h.reg.Dispatch(tc.Function.Name, tc.Function.Arguments)
			if err != nil {
				result = fmt.Sprintf("error executing %s: %v", tc.Function.Name, err)
			}
			msgs = append(msgs, Message{Role: "assistant", Content: reply.Content, ToolCalls: reply.ToolCalls})
			msgs = append(msgs, Message{Role: "tool", ToolResult: result})
		}
		return h.chatStream(msgs, depth+1, onToken)
	}

	return h.client.ChatStream(msgs, nil, onToken)
}

func (h *ChatHandler) Stop() {}
