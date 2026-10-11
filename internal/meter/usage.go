package meter

import (
	"bytes"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/provider"
)

// Bounds on what a usage parser buffers. Exceeding them makes Final report
// ok=false (the reservation is charged), never an error on the stream.
const (
	// maxBufferedBody caps a buffered non-streamed JSON body.
	maxBufferedBody = 8 << 20
	// maxEventSize caps one SSE event (all its data lines) or one element of
	// a streamed JSON array. OpenAI's response.completed event carries the
	// whole response, hence the generous size.
	maxEventSize = 8 << 20
)

// HeaderObserver is implemented by usage parsers that can use response
// headers (e.g. Gemini's x-gemini-service-tier). The proxy should call it,
// if implemented, before writing the body.
type HeaderObserver interface {
	ObserveResponseHeader(h http.Header)
}

// NewUsageParser returns an incremental parser for a response of the given
// endpoint. The provider used for pricing detail is inferred from the
// endpoint kind (OpenAI-style kinds are priced against "openai"); use
// NewProviderUsageParser when the provider name is known.
func (m *Meter) NewUsageParser(ep provider.Endpoint, stream bool) UsageParser {
	prov := ""
	switch ep.Kind {
	case provider.KindAnthropicMessages:
		prov = "anthropic"
	case provider.KindOpenAIChat, provider.KindOpenAIResponses, provider.KindOpenAIEmbeddings:
		prov = "openai"
	case provider.KindGeminiGenerate, provider.KindGeminiEmbed:
		prov = "gemini"
	}
	return m.NewProviderUsageParser(prov, ep, stream)
}

// NewProviderUsageParser is NewUsageParser with an explicit provider name,
// used to price response detail (service tier, regional inference, tool
// fees, modality, cache TTL split) that Usage alone cannot carry.
//
// The returned parser is safe for concurrent use. Write never fails and
// never blocks on I/O; memory is bounded by maxBufferedBody/maxEventSize.
// The format (single JSON body, SSE, or streamed JSON array) is detected from
// the first non-blank byte, so stream is advisory.
func (m *Meter) NewProviderUsageParser(providerName string, ep provider.Endpoint, stream bool) UsageParser {
	return &usageParser{m: m, prov: strings.ToLower(providerName), kind: ep.Kind, stream: stream}
}

type parseMode int

const (
	modeUnknown parseMode = iota
	modeJSON
	modeSSE
	modeArray
)

type usageParser struct {
	mu     sync.Mutex
	m      *Meter
	prov   string
	kind   string
	stream bool

	mode   parseMode
	failed bool // something was lost or malformed: usage is unreliable

	// modeJSON
	buf []byte

	// modeSSE
	line         []byte
	lineOverflow bool
	lastCR       bool
	evData       []byte
	evHasData    bool

	// modeArray
	arr arrayScanner

	// results
	d          usageDetail
	model      string
	gotUsage   bool
	started    bool // anthropic message_start
	stopped    bool // anthropic message_stop / responses terminal event
	finished   bool // gemini: a candidate reported finishReason
	usageFinal bool // gemini: usage seen at/after the finishing chunk
	headerTier string
	// unpricedTool is set when the response shows a tool whose charge is
	// not in the usage and cannot be priced: Final then reports ok=false.
	unpricedTool bool
	// ground is Gemini grounding seen per candidate index.
	ground map[int]*geminiGround
}

// ObserveResponseHeader implements HeaderObserver.
func (u *usageParser) ObserveResponseHeader(h http.Header) {
	if h == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if v := strings.TrimSpace(h.Get("X-Gemini-Service-Tier")); v != "" {
		u.headerTier = strings.ToLower(v)
	}
}

// Write consumes response bytes. It always returns len(p), nil.
func (u *usageParser) Write(p []byte) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := len(p)
	if u.failed && u.mode != modeUnknown {
		return n, nil
	}
	if u.mode == modeUnknown {
		p = bytes.TrimPrefix(p, []byte("\xef\xbb\xbf"))
		p = bytes.TrimLeft(p, " \t\r\n")
		if len(p) == 0 {
			return n, nil
		}
		switch p[0] {
		case '{':
			u.mode = modeJSON
		case '[':
			u.mode = modeArray
		default:
			u.mode = modeSSE
		}
	}
	switch u.mode {
	case modeJSON:
		if len(u.buf)+len(p) > maxBufferedBody {
			u.failed = true
			u.buf = nil
			return n, nil
		}
		u.buf = append(u.buf, p...)
	case modeSSE:
		u.writeSSE(p)
	case modeArray:
		u.arr.write(p, u.handleJSON)
		if u.arr.overflow || u.arr.bad {
			u.failed = true
		}
	}
	return n, nil
}

// ---- SSE framing (WHATWG event-stream) ----

func (u *usageParser) writeSSE(p []byte) {
	for len(p) > 0 {
		if u.lastCR && p[0] == '\n' {
			p = p[1:]
			u.lastCR = false
			continue
		}
		u.lastCR = false
		i := bytes.IndexAny(p, "\r\n")
		if i < 0 {
			u.appendLine(p)
			return
		}
		u.appendLine(p[:i])
		u.lastCR = p[i] == '\r'
		u.endLine()
		p = p[i+1:]
	}
}

func (u *usageParser) appendLine(b []byte) {
	if u.lineOverflow {
		return
	}
	if len(u.line)+len(b) > maxEventSize {
		u.lineOverflow = true
		u.line = nil
		return
	}
	u.line = append(u.line, b...)
}

func (u *usageParser) endLine() {
	line := u.line
	overflow := u.lineOverflow
	u.line = u.line[:0]
	u.lineOverflow = false
	if overflow {
		u.failed = true
		return
	}
	if len(line) == 0 {
		u.dispatch()
		return
	}
	if line[0] == ':' {
		return // comment
	}
	field, value, found := bytes.Cut(line, []byte(":"))
	if found && len(value) > 0 && value[0] == ' ' {
		value = value[1:]
	}
	if string(field) != "data" {
		return // event, id, retry: the data's own "type" is what matters
	}
	if len(u.evData)+len(value)+1 > maxEventSize {
		u.failed = true
		u.evData = nil
		u.evHasData = false
		return
	}
	if u.evHasData {
		u.evData = append(u.evData, '\n')
	}
	u.evData = append(u.evData, value...)
	u.evHasData = true
}

func (u *usageParser) dispatch() {
	if !u.evHasData {
		return
	}
	data := u.evData
	u.evData = u.evData[:0]
	u.evHasData = false
	d := bytes.TrimSpace(data)
	if len(d) == 0 || bytes.Equal(d, []byte("[DONE]")) {
		return
	}
	u.handleJSON(d)
}

// ---- streamed JSON array framing (Gemini without alt=sse) ----

type arrayScanner struct {
	depth      int
	inStr, esc bool
	collecting bool
	skipping   bool
	elem       []byte
	closed     bool
	overflow   bool
	bad        bool
}

func (a *arrayScanner) write(p []byte, emit func([]byte)) {
	for _, c := range p {
		if a.closed {
			if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
				a.bad = true
			}
			continue
		}
		if a.collecting {
			if len(a.elem) < maxEventSize {
				a.elem = append(a.elem, c)
			} else {
				a.overflow = true
				a.collecting = false
				a.skipping = true
				a.elem = nil
			}
		}
		if a.inStr {
			switch {
			case a.esc:
				a.esc = false
			case c == '\\':
				a.esc = true
			case c == '"':
				a.inStr = false
			}
			continue
		}
		switch c {
		case '"':
			a.inStr = true
		case '{', '[':
			a.depth++
			if a.depth == 2 && c == '{' && !a.collecting {
				a.collecting = true
				a.skipping = false
				a.elem = append(a.elem[:0], c)
			}
		case '}', ']':
			a.depth--
			if a.depth < 0 {
				a.bad = true
				a.depth = 0
			}
			if a.depth == 1 && (a.collecting || a.skipping) {
				if a.collecting {
					emit(a.elem)
				}
				a.collecting = false
				a.skipping = false
				a.elem = a.elem[:0]
			}
			if a.depth == 0 && c == ']' {
				a.closed = true
			}
		}
	}
}

// ---- per-provider JSON handling ----

type anthUsage struct {
	InputTokens              *int64 `json:"input_tokens"`
	OutputTokens             *int64 `json:"output_tokens"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     *int64 `json:"cache_read_input_tokens"`
	CacheCreation            *struct {
		Ephemeral5m *int64 `json:"ephemeral_5m_input_tokens"`
		Ephemeral1h *int64 `json:"ephemeral_1h_input_tokens"`
	} `json:"cache_creation"`
	// ServerToolUse counts server tool invocations by name
	// ("web_search_requests", "code_execution_requests", ...).
	ServerToolUse map[string]json.RawMessage `json:"server_tool_use"`
	Speed         *string                    `json:"speed"`
	InferenceGeo  *string                    `json:"inference_geo"`
}

type anthEnvelope struct {
	Type    string     `json:"type"`
	Model   string     `json:"model"`
	Usage   *anthUsage `json:"usage"`
	Message *struct {
		Model string     `json:"model"`
		Usage *anthUsage `json:"usage"`
	} `json:"message"`
}

type oaiTokenDetails struct {
	CachedTokens     *int64 `json:"cached_tokens"`
	CacheWriteTokens *int64 `json:"cache_write_tokens"`
	ReasoningTokens  *int64 `json:"reasoning_tokens"`
}

type oaiUsage struct {
	// Chat Completions / Embeddings
	PromptTokens            *int64           `json:"prompt_tokens"`
	CompletionTokens        *int64           `json:"completion_tokens"`
	PromptTokensDetails     *oaiTokenDetails `json:"prompt_tokens_details"`
	CompletionTokensDetails *oaiTokenDetails `json:"completion_tokens_details"`
	// Responses
	InputTokens         *int64           `json:"input_tokens"`
	OutputTokens        *int64           `json:"output_tokens"`
	InputTokensDetails  *oaiTokenDetails `json:"input_tokens_details"`
	OutputTokensDetails *oaiTokenDetails `json:"output_tokens_details"`
	// OpenRouter: USD as a decimal number.
	Cost *json.Number `json:"cost"`
}

type oaiResponseObj struct {
	Object      string          `json:"object"`
	Model       string          `json:"model"`
	ServiceTier string          `json:"service_tier"`
	Status      string          `json:"status"`
	Usage       *oaiUsage       `json:"usage"`
	Output      []oaiOutputItem `json:"output"`
}

type oaiOutputItem struct {
	Type string `json:"type"`
}

type oaiEnvelope struct {
	Type        string          `json:"type"`
	Object      string          `json:"object"`
	Model       string          `json:"model"`
	ServiceTier string          `json:"service_tier"`
	Usage       *oaiUsage       `json:"usage"`
	Response    *oaiResponseObj `json:"response"`
	Error       json.RawMessage `json:"error"`
}

type geminiModality struct {
	Modality   string `json:"modality"`
	TokenCount int64  `json:"tokenCount"`
}

type geminiUsage struct {
	PromptTokenCount           *int64           `json:"promptTokenCount"`
	CandidatesTokenCount       *int64           `json:"candidatesTokenCount"`
	CachedContentTokenCount    *int64           `json:"cachedContentTokenCount"`
	ThoughtsTokenCount         *int64           `json:"thoughtsTokenCount"`
	ToolUsePromptTokenCount    *int64           `json:"toolUsePromptTokenCount"`
	PromptTokensDetails        []geminiModality `json:"promptTokensDetails"`
	CacheTokensDetails         []geminiModality `json:"cacheTokensDetails"`
	ToolUsePromptTokensDetails []geminiModality `json:"toolUsePromptTokensDetails"`
}

type geminiGroundingMetadata struct {
	WebSearchQueries []string        `json:"webSearchQueries"`
	SearchEntryPoint json.RawMessage `json:"searchEntryPoint"`
	GroundingChunks  []struct {
		Maps json.RawMessage `json:"maps"`
	} `json:"groundingChunks"`
	GoogleMapsWidgetContextToken string `json:"googleMapsWidgetContextToken"`
}

// geminiGround is what a candidate's grounding metadata showed so far.
type geminiGround struct {
	search  bool
	queries int64 // most non-empty webSearchQueries seen in one chunk
	maps    bool
}

type geminiEnvelope struct {
	Candidates []struct {
		Index             int                      `json:"index"`
		FinishReason      string                   `json:"finishReason"`
		GroundingMetadata *geminiGroundingMetadata `json:"groundingMetadata"`
	} `json:"candidates"`
	UsageMetadata *geminiUsage    `json:"usageMetadata"`
	ModelVersion  string          `json:"modelVersion"`
	Error         json.RawMessage `json:"error"`
}

func (u *usageParser) handleJSON(data []byte) {
	switch u.kind {
	case provider.KindAnthropicMessages:
		u.handleAnthropic(data)
	case provider.KindOpenAIChat, provider.KindOpenAIResponses, provider.KindOpenAIEmbeddings:
		u.handleOpenAI(data)
	case provider.KindGeminiGenerate, provider.KindGeminiEmbed:
		u.handleGemini(data)
	default:
		u.failed = true
	}
}

func nonNeg(vs ...*int64) bool {
	for _, v := range vs {
		if v != nil && *v < 0 {
			return false
		}
	}
	return true
}

func (u *usageParser) handleAnthropic(data []byte) {
	var e anthEnvelope
	if err := json.Unmarshal(data, &e); err != nil {
		u.failed = true
		return
	}
	switch e.Type {
	case "message_start":
		if e.Message == nil || e.Message.Usage == nil {
			u.failed = true
			return
		}
		u.started = true
		if e.Message.Model != "" {
			u.model = e.Message.Model
		}
		u.mergeAnthropic(e.Message.Usage)
	case "message_delta":
		if e.Usage != nil {
			u.mergeAnthropic(e.Usage)
		}
	case "message_stop":
		u.stopped = true
	case "message": // non-streamed body
		if e.Usage == nil {
			u.failed = true
			return
		}
		u.started, u.stopped = true, true
		u.model = e.Model
		u.mergeAnthropic(e.Usage)
	case "error":
		u.failed = true
	}
}

func (u *usageParser) mergeAnthropic(a *anthUsage) {
	if !nonNeg(a.InputTokens, a.OutputTokens, a.CacheCreationInputTokens, a.CacheReadInputTokens) {
		u.failed = true
		return
	}
	u.gotUsage = true
	if a.InputTokens != nil {
		u.d.InputTokens = *a.InputTokens
	}
	if a.OutputTokens != nil {
		u.d.OutputTokens = *a.OutputTokens // cumulative in message_delta
	}
	if a.CacheCreationInputTokens != nil {
		u.d.CacheWriteTokens = *a.CacheCreationInputTokens
	}
	if a.CacheReadInputTokens != nil {
		u.d.CacheReadTokens = *a.CacheReadInputTokens
	}
	if cc := a.CacheCreation; cc != nil && cc.Ephemeral5m != nil {
		if !nonNeg(cc.Ephemeral5m, cc.Ephemeral1h) {
			u.failed = true
			return
		}
		u.d.split5m = true
		u.d.cacheWrite5m = *cc.Ephemeral5m
	}
	for name, raw := range a.ServerToolUse {
		if isNull(raw) {
			continue
		}
		n, err := intValue(name, raw, false)
		if err != nil {
			u.failed = true
			return
		}
		switch name {
		case "web_search_requests":
			u.d.webSearchRequests = n // cumulative in message_delta
		case "web_fetch_requests", "tool_search_requests":
			// No charge beyond tokens.
		default:
			// code_execution_requests (billed per container-hour) or a
			// server tool this table does not know: cannot be priced.
			if n > 0 {
				u.unpricedTool = true
			}
		}
	}
	if a.Speed != nil {
		if *a.Speed == "standard" {
			u.d.tier = ""
		} else {
			u.d.tier = *a.Speed
		}
	}
	if a.InferenceGeo != nil {
		g := strings.ToLower(*a.InferenceGeo)
		// Anything other than global routing is regional (fail closed).
		u.d.regional = g != "" && g != "global"
	}
}

func (u *usageParser) handleOpenAI(data []byte) {
	var e oaiEnvelope
	if err := json.Unmarshal(data, &e); err != nil {
		u.failed = true
		return
	}
	if len(e.Error) > 0 && !isNull(e.Error) {
		u.failed = true
		return
	}
	switch {
	case e.Response != nil && strings.HasPrefix(e.Type, "response."):
		// Responses API stream event.
		switch e.Type {
		case "response.completed", "response.incomplete", "response.failed":
			u.stopped = true
			u.applyResponseObj(e.Response)
		}
	case e.Type == "error":
		u.failed = true
	case e.Object == "response":
		// Non-streamed Responses API body.
		u.stopped = true
		var out struct {
			Output []oaiOutputItem `json:"output"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			u.failed = true
			return
		}
		u.applyResponseObj(&oaiResponseObj{Object: e.Object, Model: e.Model, ServiceTier: e.ServiceTier, Usage: e.Usage, Output: out.Output})
	default:
		// Chat Completions (body or chunk) and Embeddings.
		if e.Model != "" {
			u.model = e.Model
		}
		if e.ServiceTier != "" {
			u.d.tier = e.ServiceTier
		}
		if e.Usage != nil {
			u.applyOpenAIUsage(e.Usage)
		}
	}
}

// applyOutputItems counts billable built-in tool calls in a Responses API
// output list. Tools billed outside the response's usage (code interpreter
// containers, image generation) cannot be priced here.
func (u *usageParser) applyOutputItems(items []oaiOutputItem) {
	var web, file int64
	for _, it := range items {
		switch it.Type {
		case "web_search_call":
			web++
		case "file_search_call":
			file++
		case "code_interpreter_call", "image_generation_call":
			u.unpricedTool = true
		}
	}
	u.d.webSearchCalls, u.d.fileSearchCalls = web, file
}

func (u *usageParser) applyResponseObj(r *oaiResponseObj) {
	if r.Model != "" {
		u.model = r.Model
	}
	if r.ServiceTier != "" {
		u.d.tier = r.ServiceTier
	}
	u.applyOutputItems(r.Output)
	if r.Usage != nil {
		u.applyOpenAIUsage(r.Usage)
	}
}

func (u *usageParser) applyOpenAIUsage(x *oaiUsage) {
	in, out := x.PromptTokens, x.CompletionTokens
	inD, outD := x.PromptTokensDetails, x.CompletionTokensDetails
	if x.InputTokens != nil || x.OutputTokens != nil {
		in, out = x.InputTokens, x.OutputTokens
		inD, outD = x.InputTokensDetails, x.OutputTokensDetails
	}
	if in == nil {
		u.failed = true
		return
	}
	var cached, written, reasoning *int64
	if inD != nil {
		cached, written = inD.CachedTokens, inD.CacheWriteTokens
	}
	if outD != nil {
		reasoning = outD.ReasoningTokens
	}
	if !nonNeg(in, out, cached, written, reasoning) {
		u.failed = true
		return
	}
	u.gotUsage = true
	total := *in
	var c, w int64
	if cached != nil {
		c = *cached
	}
	if written != nil {
		w = *written
	}
	// prompt/input tokens include cached and cache-write tokens.
	u.d.InputTokens = max(total-c-w, 0)
	u.d.CacheReadTokens = c
	u.d.CacheWriteTokens = w
	u.d.OutputTokens = 0
	if out != nil {
		u.d.OutputTokens = *out
	}
	u.d.ReasoningTokens = 0
	if reasoning != nil {
		u.d.ReasoningTokens = *reasoning
	}
	if x.Cost != nil {
		micros, ok := usdToMicrosCeil(string(*x.Cost))
		if !ok {
			u.failed = true
			return
		}
		u.d.ProviderCostMicros = int64(micros)
	}
}

// usdToMicrosCeil converts a decimal USD amount to micro-USD, rounding up.
func usdToMicrosCeil(s string) (money.Micros, bool) {
	r, ok := new(big.Rat).SetString(strings.TrimSpace(s))
	if !ok || r.Sign() < 0 {
		return 0, false
	}
	r.Mul(r, big.NewRat(1_000_000, 1))
	q, rem := new(big.Int).QuoRem(r.Num(), r.Denom(), new(big.Int))
	if rem.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsInt64() {
		return maxMicros, true
	}
	return money.Micros(q.Int64()), true
}

func (u *usageParser) handleGemini(data []byte) {
	var e geminiEnvelope
	if err := json.Unmarshal(data, &e); err != nil {
		u.failed = true
		return
	}
	if len(e.Error) > 0 && !isNull(e.Error) {
		u.failed = true
		return
	}
	if e.ModelVersion != "" {
		u.model = e.ModelVersion
	}
	finishing := false
	for _, c := range e.Candidates {
		if c.FinishReason != "" && c.FinishReason != "FINISH_REASON_UNSPECIFIED" {
			finishing = true
		}
		if gm := c.GroundingMetadata; gm != nil {
			u.observeGrounding(c.Index, gm)
		}
	}
	if finishing {
		u.finished = true
	}
	g := e.UsageMetadata
	if g == nil {
		return
	}
	if !nonNeg(g.PromptTokenCount, g.CandidatesTokenCount, g.CachedContentTokenCount, g.ThoughtsTokenCount, g.ToolUsePromptTokenCount) {
		u.failed = true
		return
	}
	val := func(p *int64) int64 {
		if p == nil {
			return 0
		}
		return *p
	}
	prompt, cached, tool := val(g.PromptTokenCount), val(g.CachedContentTokenCount), val(g.ToolUsePromptTokenCount)
	thoughts := val(g.ThoughtsTokenCount)
	u.gotUsage = true
	u.usageFinal = u.finished
	// promptTokenCount includes cached content; tool-use prompt tokens are
	// reported separately and billed as input.
	u.d.InputTokens = satAddTokens(max(prompt-cached, 0), tool)
	u.d.CacheReadTokens = cached
	u.d.CacheWriteTokens = 0
	// Thinking tokens are billed at the output rate and not included in
	// candidatesTokenCount.
	u.d.OutputTokens = satAddTokens(val(g.CandidatesTokenCount), thoughts)
	u.d.ReasoningTokens = thoughts

	u.d.modKnown = len(g.PromptTokensDetails) > 0 || (prompt == 0 && tool == 0)
	in := map[string]int64{}
	for _, d := range g.PromptTokensDetails {
		in[strings.ToUpper(d.Modality)] += max(d.TokenCount, 0)
	}
	for _, d := range g.ToolUsePromptTokensDetails {
		in[strings.ToUpper(d.Modality)] += max(d.TokenCount, 0)
	}
	cr := map[string]int64{}
	for _, d := range g.CacheTokensDetails {
		cr[strings.ToUpper(d.Modality)] += max(d.TokenCount, 0)
	}
	if cached > 0 && len(g.CacheTokensDetails) == 0 {
		u.d.modKnown = false // cannot split cached tokens by modality
	}
	for k, v := range cr {
		in[k] = max(in[k]-v, 0) // promptTokensDetails include cached tokens
	}
	u.d.modIn, u.d.modCR = in, cr
}

func (u *usageParser) observeGrounding(idx int, gm *geminiGroundingMetadata) {
	if u.ground == nil {
		u.ground = map[int]*geminiGround{}
	}
	g := u.ground[idx]
	if g == nil {
		if len(u.ground) >= maxGroundCandidates {
			u.failed = true
			return
		}
		g = &geminiGround{}
		u.ground[idx] = g
	}
	var q int64
	for _, s := range gm.WebSearchQueries {
		if strings.TrimSpace(s) != "" {
			q++
		}
	}
	if q > 0 || (len(gm.SearchEntryPoint) > 0 && !isNull(gm.SearchEntryPoint)) {
		g.search = true
	}
	g.queries = max(g.queries, q)
	if gm.GoogleMapsWidgetContextToken != "" {
		g.maps = true
	}
	for _, c := range gm.GroundingChunks {
		if len(c.Maps) > 0 && !isNull(c.Maps) {
			g.maps = true
		}
	}
}

// maxGroundCandidates bounds the per-candidate grounding state.
const maxGroundCandidates = 64

// resolveGrounding turns observed Gemini grounding into billable counts
// under the model's fees. It returns false when grounding was used but its
// fee cannot be determined (no fee in the table, or per-query billing
// without a reported query count).
func (u *usageParser) resolveGrounding(d *usageDetail, fees Fees) bool {
	for _, g := range u.ground {
		if g.search {
			switch {
			case fees.GoogleSearchQuery > 0:
				if g.queries == 0 {
					return false
				}
				d.searchQueries = satAddTokens(d.searchQueries, g.queries)
			case fees.GoogleSearchPrompt > 0:
				d.searchPrompts++
			default:
				return false
			}
		}
		if g.maps {
			switch {
			case fees.GoogleMapsQuery > 0:
				return false // Maps query counts are not reported
			case fees.GoogleMapsPrompt > 0:
				d.mapsPrompts++
			default:
				return false
			}
		}
	}
	return true
}

func (u *usageParser) grounded() bool {
	for _, g := range u.ground {
		if g.search || g.maps {
			return true
		}
	}
	return false
}

// Final reports the usage once the body is complete.
func (u *usageParser) Final() (Usage, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	switch u.mode {
	case modeJSON:
		if !u.failed {
			if !json.Valid(u.buf) {
				u.failed = true
			} else {
				u.handleJSON(u.buf)
			}
		}
	case modeSSE:
		// A trailing event without its terminating blank line was cut off and
		// is discarded (WHATWG rule); that loses usage, which is fail-safe.
		if u.lineOverflow {
			u.failed = true
		}
	case modeArray:
		if !u.arr.closed {
			u.failed = true
		}
	case modeUnknown:
		return Usage{}, false
	}
	if u.failed || !u.gotUsage {
		return Usage{}, false
	}
	if u.unpricedTool {
		// A tool billed outside token usage ran: charge the reservation.
		return Usage{}, false
	}
	switch u.kind {
	case provider.KindAnthropicMessages:
		if !u.started || !u.stopped {
			return Usage{}, false
		}
	case provider.KindOpenAIResponses:
		if !u.stopped {
			return Usage{}, false
		}
	case provider.KindGeminiGenerate:
		if u.mode != modeJSON && !u.usageFinal {
			return Usage{}, false
		}
	}
	if u.headerTier != "" {
		u.d.tier = u.headerTier
	}
	out := u.d.Usage
	out.Model = u.model
	if out.ProviderCostMicros > 0 {
		return out, true
	}
	hasExtras := !isStandardTier(u.d.tier) || u.d.regional || u.d.hasFees()
	pr, ok := u.m.lookup(u.prov, out.Model)
	if !ok {
		if u.grounded() || u.d.hasFees() {
			// A model without a price has no fee table to price provider
			// tool calls (web search, file search, grounding) with: charge
			// the reservation instead of settling the fees at $0.
			return Usage{}, false
		}
		if hasExtras && out.Model == "" {
			// The price-changing detail cannot be applied without a model;
			// the caller would otherwise price the request too cheaply.
			return Usage{}, false
		}
		return out, true
	}
	d := u.d
	d.Usage = out
	fees := u.m.Pricing.feesFor(u.prov, pr)
	if !u.resolveGrounding(&d, fees) {
		return Usage{}, false
	}
	if d.needsDetailPricing(pr) {
		// A zero cost (no tokens, no fees) is left to Cost, which agrees.
		out.ProviderCostMicros = int64(priceUsage(pr, d, fees))
	}
	return out, true
}
