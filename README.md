# Alfred KeePass Workflow
This Alfred workflow allows you to quickly search and copy passwords from your KeePass database without having to open the KeePass application.

[![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Alfred%205%20Workflow%20to%20quickly%20search%20and%20copy%20KeePass%20attributes.&hashtags=Alfred,KeePassXC&url=https://github.com/mikyk10/alfred-keepass) <img src="https://img.shields.io/github/last-commit/mikyk10/alfred-keepass"> <img src="https://img.shields.io/github/downloads/mikyk10/alfred-keepass/total">

![demo](https://user-images.githubusercontent.com/4987502/218909942-34f80265-de15-4338-8238-b7cd2d2d6ddf.gif)

## Features

- Built on Golang for faster search performance. 
- KDB3 and KDB4 are supported.
- TOTP, attributes and attached files are supported powered by keepassxc-cli
- Fuzzy search for the faster result
- Simple and intuitive interface.

## Installation
1. [Download the .alfredworkflow](https://github.com/mikyk10/alfred-keepass/tags) file from the [releases](https://github.com/mikyk10/alfred-keepass/tags) section.
2. Double click the downloaded file to import it into Alfred.

or if you prefer building the app on your own. See Contribution for more detail.

3. Fill out the configuration with your KeePassXC database file path (and key file if you use one).

<img width="1100" alt="installation" src="https://user-images.githubusercontent.com/4987502/218407644-7069c96a-7c63-4b94-8385-2c30e3bf45c0.png">

4. Type `kp:setpass` in Alfred and enter your master password. The first time, macOS also asks you to choose a password for a new keychain dedicated to this workflow (`~/Library/Keychains/alfred-keepass.keychain-db`); the master password is stored there, not in the workflow configuration. Run `kp:setpass` again to change it.

5. Run the following command in terminal to make a symbolic link.

```
ln -s /Applications/KeePassXC.app//Contents/MacOS/keepassxc-cli /usr/local/bin
```

## Usage
1. Trigger Alfred by pressing the Alfred hotkey.
2. Type `kp` followed by the name of the password you are searching for.
3. Select the desired password from the list of results.
4. The password will be automatically copied to your clipboard.

You can filter by tag by prefixing a keyword with `#`, e.g. `kp gmail #work`. Tag terms and normal keywords can be combined, and tag matching is partial and case-insensitive.

Alternatively you can also copy `username` and `URL` by holding CMD or ALT before pressing Enter.

Hold CTRL+SHIFT before pressing Enter to copy the TOTP token of entries that have one.

### Upgrading from an earlier version

The master password is no longer read from the workflow configuration. After upgrading, run `kp:setpass` once to store it in the keychain; the old plain-text value can be discarded.

### About the keychain

The dedicated keychain locks itself after 5 minutes of inactivity and when your Mac sleeps. While it is locked nothing can read the master password; the next search shows the macOS unlock dialog. To change the timeout (in seconds):

```
security set-keychain-settings -l -u -t 600 ~/Library/Keychains/alfred-keepass.keychain-db
```

While it is unlocked, the item can be read through the `security` command by any process running as your user without a prompt, so the lock timeout is what limits the exposure. Versions that stored the password in the login keychain are migrated by running `kp:setpass` once; the old login keychain item is deleted.

## Limitation

* Currently `master password` encrypted .kdbx is supported. Not much tested yet.

## Requirements

* Alfred 5 or later with the Powerpack upgrade.
* A KeePass database.
* KeepassXC for TOTP.

## Contribution
I am very welcome any contributions to improve it. If you have any bug reports, feature requests, or code contributions, please open an issue or pull request on the GitHub repository.

If you add a new feature, please make sure that any code comes with a working test suite as much as you can to ensure the quality and reliability of the code. This will help to maintain the high standards of the project and ensure that any changes are thoroughly tested.

### Prerequisites
Knowledge of Go programming language is required to contribute to this Alfred workflow. Please make sure to have Go installed on your development machine.

### Building
* `make` builds `bin/KeePass.alfredworkflow` and opens it to import into Alfred.
* `make update` copies the freshly built binary into your installed workflow and copies its `info.plist` back into `src/`, so edits made in Alfred's workflow editor can be committed. The installed workflow is found by bundle id in your Alfred preferences; set `ALFRED_WORKFLOW_DIR=/path/to/user.workflow.XXXX` to point at it explicitly.

## Disclaimer
This Alfred workflow is provided "as is" with no express or implied warranties. The authors and copyright holders are not responsible for any liability arising from the use of this software. By using it, you agree to take full responsibility for any consequences that may arise.

Please note that this workflow has not yet been fully confirmed not to contain any malicious code across all dependencies.

## TODO
* Write `README.md`
