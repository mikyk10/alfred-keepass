# Alfred KeePass Workflow
This Alfred workflow allows you to quickly search and copy passwords from your KeePass database without having to open the KeePass application.

https://user-images.githubusercontent.com/4987502/218271746-efd28905-5d78-4c5f-b1b2-1fbd70b39e7f.mov

## Features
- Built on Golang for blazing fast performance. 
- Simple and intuitive interface.

## Installation
- [Download the .alfredworkflow](https://github.com/mikyk10/alfred-keepass/tags) file from the [releases](https://github.com/mikyk10/alfred-keepass/tags) section.
- Double click the downloaded file to import it into Alfred.

or if you extremely care about security, you can build it on your own. See Contribution for more detail.

- Clone the repository. (You could fully inspect code base before proceeding to the next.)
- run `make`

## Setup
Before using this workflow, make sure you follow these steps.

1. Trigger Alfred by pressing the Alfred hotkey and type `kp`. By doing this, a default TOML configuration file, `~/.alkeepass`, will be created under the home directory.
2.  Edit the configuration file using your favorite editor or just enter `open -a TextEdit ~/.alkeepass` in Terminal app. This is necessary for securely storing your KeePass file location, credentials.

## Usage
1. Trigger Alfred by pressing the Alfred hotkey.
2. Type `kp` followed by the name of the password you are searching for.
3. Select the desired password from the list of results.
4. The password will be automatically copied to your clipboard.

Alternatively you can also copy `username` and `URL` by holding CMD or ALT before pressing Enter.

## Limitation

* Currently `master passoword` encrypted .kdbx is supported. Not much tested yet.

## Requirements

* Alfred 4 or later with the Powerpack upgrade.
* A KeePass database.
* KeepassXC for TOTP.

## Contribution
I am very welcome any contributions to improve it. If you have any bug reports, feature requests, or code contributions, please open an issue or pull request on the GitHub repository.

If you add a new feature, please make sure that any code comes with a working test suite as much as you can to ensure the quality and reliability of the code. This will help to maintain the high standards of the project and ensure that any changes are thoroughly tested.

### Prerequisites
Knowledge of Go programming language is required to contribute to this Alfred workflow. Please make sure to have Go installed on your development machine.

## Note

If you've used the very first version, `v0.0.1`, the newer version does not use `~/.alkeepass` for its configuration store. You can delete the file.


## Disclaimer
This Alfred workflow is provided "as is" with no express or implied warranties. The authors and copyright holders are not responsible for any liability arising from the use of this software. By using it, you agree to take full responsibility for any consequences that may arise.

Please note that this workflow has been confirmed to not contain any malicious code. However, it is important to regularly review your security practices to ensure the safety of your sensitive information.

## TODO
* Write `README.md`
