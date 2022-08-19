package callbacks

const (
	TypeText       = "text"
	TypePassword   = "password"
	TypeImage      = "image"
	TypeHttpStatus = "httpstatus"
	TypeAutoSubmit = "autosubmit"
	TypeOptions    = "options"
	TypeActions    = "actions"
)

type Callback struct {
	Name       string            `json:"name,omitempty"`
	Type       string            `json:"type"`
	Value      string            `json:"value"`
	Prompt     string            `json:"prompt,omitempty"`
	Validation string            `json:"validation,omitempty"`
	Required   bool              `json:"required,omitempty"`
	Options    []string          `json:"options,omitempty"`
	Properties map[string]string `json:"properties,omitempty"` //TODO v2 move to map[string]interface{}
	Error      string            `json:"error,omitempty"`
}

// Request TODO move to more appropriate package
type Request struct {
	Module    string     `json:"module,omitempty"`
	Callbacks []Callback `json:"callbacks,omitempty"`
	FlowId    string     `json:"flowId,omitempty"`
}

// Response TODO move to more appropriate package
type Response struct {
	Module    string     `json:"module,omitempty"`
	Callbacks []Callback `json:"callbacks,omitempty"`
	Token     string     `json:"token,omitempty"`
	Type      string     `json:"type,omitempty"`   //returns token type
	FlowId    string     `json:"flowId,omitempty"` //TODO add error
}
