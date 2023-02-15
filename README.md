# Alfred KeePass Workflow
This Alfred workflow allows you to quickly search and copy passwords from your KeePass database without having to open the KeePass application.

<img src="https://img.shields.io/github/license/mikyk10/alfred-keepass"> <img src="https://img.shields.io/github/last-commit/mikyk10/alfred-keepass"> <img src="https://img.shields.io/github/downloads/mikyk10/alfred-keepass/total">

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

3. Fill out the configuration with your KeePassXC database file path, master password, and key file(not yet supported).

<img width="1100" alt="installation" src="https://user-images.githubusercontent.com/4987502/218407644-7069c96a-7c63-4b94-8385-2c30e3bf45c0.png">

## Usage
1. Trigger Alfred by pressing the Alfred hotkey.
2. Type `kp` followed by the name of the password you are searching for.
3. Select the desired password from the list of results.
4. The password will be automatically copied to your clipboard.

Alternatively you can also copy `username` and `URL` by holding CMD or ALT before pressing Enter.

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

## Disclaimer
This Alfred workflow is provided "as is" with no express or implied warranties. The authors and copyright holders are not responsible for any liability arising from the use of this software. By using it, you agree to take full responsibility for any consequences that may arise.

Please note that this workflow has been confirmed to not contain any malicious code. However, it is important to regularly review your security practices to ensure the safety of your sensitive information.

## TODO
* Write `README.md`
