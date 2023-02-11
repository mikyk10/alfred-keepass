# Alfred KeePass Workflow
This Alfred workflow allows you to quickly search and copy passwords from your KeePass database without having to open the KeePass application.

## Installation
- Download the KeePass.alfredworkflow file from the releases section.
- Double click the downloaded file to import it into Alfred.

or if you extremely care about security, you can build it on your own.

- Download the repository. (You could fully inspect code base before proceeding the next.)
- run `make`

## Setup
1. Trigger Alfred by pressing the Alfred hotkey and type `kp`.
2. Before using this workflow, make sure you to edit the configuration file, "~/.alkeepass". By doing #1, the default file will be created. This is necessary for securely storing your KeePass file location, credentials.

## Usage
1. Trigger Alfred by pressing the Alfred hotkey.
2. Type `kp` followed by the name of the password you are searching for.
3. Select the desired password from the list of results.
4. The password will be automatically copied to your clipboard.

Alternatively you can also copy `username` and `URL` by holding CMD or ALT before pressing Enter.

## Requirements
* Alfred 4 or later with the Powerpack upgrade.
* A KeePass database.

## Contribution
I am very welcome any contributions to improve it. If you have any bug reports, feature requests, or code contributions, please open an issue or pull request on the GitHub repository.

If you add a new feature, please make sure that any code comes with a working test suite to ensure the quality and reliability of the code. This will help to maintain the high standards of the project and ensure that any changes are thoroughly tested.

### Prerequisites
Knowledge of Go programming language is required to contribute to this Alfred workflow. Please make sure to have Go installed on your development machine.

## Disclaimer
This Alfred workflow is provided "as is" with no express or implied warranties. The authors and copyright holders are not responsible for any liability arising from the use of this software. By using it, you agree to take full responsibility for any consequences that may arise.

Please note that this workflow has been confirmed to not contain any malicious code. However, it is important to regularly review your security practices to ensure the safety of your sensitive information.

## TODO
* Write `README.md`