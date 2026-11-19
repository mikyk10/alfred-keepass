# Usage

`kp:setpass` to store your master password in the macOS keychain (run this once first; leave it empty if the database has no password)
`kp` {keywords}... to search entries in your .kdbx file
`kp:lock` to forget the cached key (see `Key cache` in the configuration) and lock the keychain
Prefix a keyword with `#` to filter by tag, e.g. `kp gmail #work`
In search result, hold:
  ⌘  (Command) to copy UserName
  ⌥  (Option) to copy URL
  ⇧⌥ (Shift+Option) to open URL in default browser
  ⌘⌥ (Command+Option) to copy Notes
  ⌃  (Control) to copy other attributes, attachments...
  ⌃⇧ (Control+Shift) to copy TOTP
