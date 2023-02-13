package cmd

type AlfredMods struct {
	Alt  AlfredModItem `json:"alt"`
	Cmd  AlfredModItem `json:"cmd"`
	Ctrl AlfredModItem `json:"ctrl,omitempty"`
}
type AlfredModItem struct {
	Valid    bool   `json:"valid"`
	Arg      string `json:"arg"`
	Subtitle string `json:"subtitle,omitempty"`
}
type AlfredJSONItem struct {
	Uid      string `json:"uid"`
	Title    string `json:"title"`
	Arg      string `json:"arg"`
	Subtitle string `json:"subtitle,omitempty"`
	//Icon string `json:"icon"`
	Mods AlfredMods `json:"mods"`
}

type AlfredJSON struct {
	Items []AlfredJSONItem `json:"items"`
}
