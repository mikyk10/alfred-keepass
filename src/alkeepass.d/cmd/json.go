package cmd

type AlfredMods struct {
	Alt AlfredModItem `json:"alt"`
	Cmd AlfredModItem `json:"cmd"`
}
type AlfredModItem struct {
	Valid    bool   `json:"valid"`
	Arg      string `json:"arg"`
	Subtitle string `json:"subtitle"`
}
type AlfredJSONItem struct {
	Uid      string `json:"uid"`
	Title    string `json:"title"`
	Arg      string `json:"arg"`
	Subtitle string `json:"subtitle"`
	//Icon string `json:"icon"`
	Mods AlfredMods `json:"mods"`
}

type AlfredJSON struct {
	Items []AlfredJSONItem `json:"items"`
}
