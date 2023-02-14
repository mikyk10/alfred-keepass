package cmd

type AlfredMods struct {
	Alt      AlfredModItem `json:"alt"`
	Cmd      AlfredModItem `json:"cmd"`
	Ctrl     AlfredModItem `json:"ctrl,omitempty"`
	AltShift AlfredModItem `json:"alt+shift,omitempty"`
	CmdAlt   AlfredModItem `json:"cmd+alt,omitempty"`
}
type AlfredModItem struct {
	Valid    bool        `json:"valid"`
	Arg      string      `json:"arg"`
	Subtitle string      `json:"subtitle,omitempty"`
	Icon     *AlfredIcon `json:"icon,omitempty"`
}
type AlfredIcon struct {
	Path string `json:"path"`
}
type AlfredJSONItem struct {
	Uid      string `json:"uid"`
	Title    string `json:"title"`
	Arg      string `json:"arg"`
	Subtitle string `json:"subtitle,omitempty"`
	//Icon string `json:"icon"`
	Mods      AlfredMods        `json:"mods"`
	Variables map[string]string `json:"variables,omitempty"`
}

type AlfredJSON struct {
	Items     []AlfredJSONItem `json:"items"`
	Variables struct {
		Query string `json:"query,omitempty"`
	} `json:"variables,omitempty"`
}
