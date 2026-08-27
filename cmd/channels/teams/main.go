package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"github.com/icinga/icinga-go-library/notifications/plugin"
	"github.com/icinga/icinga-notifications/internal"
)

func main() {
	plugin.Run(&Teams{})
}

// defaultCardTemplate is a Go text/template rendered over the current *plugin.NotificationRequest.
//
// It must produce ONLY the Adaptive Card "content" object. The surrounding Microsoft Teams message
// envelope ({"type":"message","attachments":[{"contentType":"...adaptive","content": <card>}]}) is
// added in Go (see SendNotification), so a broken template can never corrupt the envelope.
//
// The `json` template function marshals a value to a valid JSON literal and is the correct way to
// embed check output, object names, etc. into the card (it handles quoting and escaping).
const defaultCardTemplate = `{{- $sev := "" -}}
{{- with .Incident }}{{ $sev = printf "%s" .Severity }}{{ end -}}
{{- $color := "Accent" -}}{{- $style := "accent" -}}{{- $icon := "🔔" -}}
{{- if eq $sev "ok" -}}{{- $color = "Good" -}}{{- $style = "good" -}}{{- $icon = "✅" -}}
{{- else if or (eq $sev "warning") (eq $sev "notice") -}}{{- $color = "Warning" -}}{{- $style = "warning" -}}{{- $icon = "⚠️" -}}
{{- else if or (eq $sev "err") (eq $sev "crit") (eq $sev "alert") (eq $sev "emerg") -}}{{- $color = "Attention" -}}{{- $style = "attention" -}}{{- $icon = "🔥" -}}
{{- end -}}
{
  "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
  "type": "AdaptiveCard",
  "version": "1.4",
  "body": [
    {
      "type": "Container",
      "style": "{{ $style }}",
      "bleed": true,
      "items": [
        {
          "type": "ColumnSet",
          "columns": [
            { "type": "Column", "width": "auto", "verticalContentAlignment": "Center",
              "items": [ { "type": "TextBlock", "text": "{{ $icon }}", "size": "Large" } ] },
            { "type": "Column", "width": "stretch", "verticalContentAlignment": "Center",
              "items": [
                { "type": "TextBlock", "text": "Icinga Notification", "weight": "Bolder", "size": "Large", "color": "{{ $color }}", "spacing": "None" },
                { "type": "TextBlock", "text": {{ json .Object.Name }}, "isSubtle": true, "spacing": "None", "wrap": true }
              ] }
          ]
        }
      ]
    },
    {
      "type": "FactSet",
      "spacing": "Medium",
      "facts": [
        { "title": "Host", "value": {{ json (index .Object.Tags "host") }} }
        {{ if index .Object.Tags "service" }}, { "title": "Service", "value": {{ json (index .Object.Tags "service") }} }{{ end }}
        {{ with .Incident }}, { "title": "Schweregrad", "value": {{ json (printf "%s" .Severity) }} }{{ end }}
        , { "title": "Zeit", "value": {{ json .Event.Time }} }
      ]
    },
    {
      "type": "TextBlock",
      "text": {{ json .Event.Message }},
      "wrap": true,
      "spacing": "Medium"
    }
  ]{{ with .Object.Url }},
  "actions": [
    { "type": "Action.OpenUrl", "title": "Im Icinga Web öffnen", "url": {{ json . }} }
  ]{{ end }}
}`

// Teams is a channel plugin delivering notifications to a Microsoft Teams
// Power Automate ("Workflows") incoming webhook as an Adaptive Card.
type Teams struct {
	WebhookURL          string `json:"webhook_url"`
	CardTemplate        string `json:"card_template"`
	ResponseStatusCodes string `json:"response_status_codes"`

	tmplCard        *template.Template
	respStatusCodes []int
	mu              sync.Mutex // Protects the struct fields during concurrent RPC calls.
}

// teamsMessage is the Power Automate webhook envelope wrapping one Adaptive Card.
type teamsMessage struct {
	Type        string            `json:"type"`
	Attachments []teamsAttachment `json:"attachments"`
}

type teamsAttachment struct {
	ContentType string          `json:"contentType"`
	ContentURL  *string         `json:"contentUrl"`
	Content     json.RawMessage `json:"content"`
}

func (ch *Teams) GetInfo() *plugin.Info {
	configAttrs := plugin.ConfigOptions{
		{
			Name: "webhook_url",
			Type: "secret",
			Label: map[string]string{
				"en_US": "Webhook URL",
				"de_DE": "Webhook-URL",
			},
			Help: map[string]string{
				"en_US": "Microsoft Teams Power Automate (Workflows) incoming webhook URL. Contains a signature and should be treated as a secret.",
				"de_DE": "Microsoft-Teams-Webhook-URL (Power Automate / Workflows). Enthält eine Signatur und ist wie ein Geheimnis zu behandeln.",
			},
			Required: true,
		},
		{
			Name: "card_template",
			Type: "text",
			Label: map[string]string{
				"en_US": "Adaptive Card Template",
				"de_DE": "Adaptive-Card-Template",
			},
			Help: map[string]string{
				"en_US": "Go template over the current plugin.NotificationRequest producing the Adaptive Card content object. The Teams message envelope is added automatically.",
				"de_DE": "Go-Template über das plugin.NotificationRequest, das das Adaptive-Card-Content-Objekt erzeugt. Der Teams-Nachrichten-Envelope wird automatisch ergänzt.",
			},
			Default: defaultCardTemplate,
		},
		{
			Name: "response_status_codes",
			Type: "string",
			Label: map[string]string{
				"en_US": "Response Status Codes",
				"de_DE": "Antwort-Status-Codes",
			},
			Help: map[string]string{
				"en_US": "Comma separated list of accepted HTTP response status codes. Power Automate answers with 202 on success.",
				"de_DE": "Kommaseparierte Liste akzeptierter HTTP-Status-Codes. Power Automate antwortet im Erfolgsfall mit 202.",
			},
			Default:  "200,202",
			Required: true,
		},
	}

	return &plugin.Info{
		Name:             "Microsoft Teams",
		Version:          internal.Version.Version,
		Author:           "Icinga Community",
		ConfigAttributes: configAttrs,
	}
}

func (ch *Teams) SetConfig(jsonStr json.RawMessage) error {
	var tmp Teams
	if err := plugin.PopulateDefaults(&tmp); err != nil {
		return err
	}

	if err := json.Unmarshal(jsonStr, &tmp); err != nil {
		return err
	}

	tmplFuncs := template.FuncMap{
		"json": func(a any) (string, error) {
			data, err := json.Marshal(a)
			if err != nil {
				return "", err
			}
			return string(data), nil
		},
	}

	var err error
	tmp.tmplCard, err = template.New("card").Funcs(tmplFuncs).Parse(tmp.CardTemplate)
	if err != nil {
		return fmt.Errorf("cannot parse Adaptive Card template: %w", err)
	}

	if strings.TrimSpace(tmp.WebhookURL) == "" {
		return fmt.Errorf("webhook_url must not be empty")
	}

	codeStrs := strings.Split(tmp.ResponseStatusCodes, ",")
	tmp.respStatusCodes = make([]int, len(codeStrs))
	for i, codeStr := range codeStrs {
		code, err := strconv.Atoi(strings.TrimSpace(codeStr))
		if err != nil {
			return fmt.Errorf("cannot convert status code %q to int: %w", codeStr, err)
		}
		tmp.respStatusCodes[i] = code
	}

	ch.mu.Lock()
	defer ch.mu.Unlock()

	ch.WebhookURL = tmp.WebhookURL
	ch.CardTemplate = tmp.CardTemplate
	ch.ResponseStatusCodes = tmp.ResponseStatusCodes

	ch.tmplCard = tmp.tmplCard
	ch.respStatusCodes = tmp.respStatusCodes

	return nil
}

func (ch *Teams) SendNotification(req *plugin.NotificationRequest) error {
	ch.mu.Lock()
	webhookURL := ch.WebhookURL
	tmplCard := ch.tmplCard
	respStatusCodes := ch.respStatusCodes
	ch.mu.Unlock()

	var cardBuff bytes.Buffer
	if err := tmplCard.Execute(&cardBuff, req); err != nil {
		return fmt.Errorf("cannot execute Adaptive Card template: %w", err)
	}

	// Wrap the rendered card in the Teams envelope. json.Marshal validates the
	// RawMessage, so an invalid card surfaces here as a clear error instead of a
	// confusing HTTP 400 from Teams.
	payload := teamsMessage{
		Type: "message",
		Attachments: []teamsAttachment{{
			ContentType: "application/vnd.microsoft.card.adaptive",
			ContentURL:  nil,
			Content:     json.RawMessage(cardBuff.Bytes()),
		}},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("rendered Adaptive Card is not valid JSON: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := http.DefaultClient.Do(httpReq) // #nosec G704 -- no SSRF, trusted user input
	if err != nil {
		return err
	}
	respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 2048))
	_ = httpResp.Body.Close()

	if !slices.Contains(respStatusCodes, httpResp.StatusCode) {
		if msg := strings.TrimSpace(string(respBody)); msg != "" {
			return fmt.Errorf("unaccepted HTTP response status code %d not in %v: %s",
				httpResp.StatusCode, respStatusCodes, msg)
		}
		return fmt.Errorf("unaccepted HTTP response status code %d not in %v",
			httpResp.StatusCode, respStatusCodes)
	}

	return nil
}
