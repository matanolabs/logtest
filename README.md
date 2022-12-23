
# `logtest` - Interactive workflow to build & test new Matano log sources locally using your IDE

## Installation

#### Prerequisites

- **1) Install [difftastic](https://difftastic.wilfred.me.uk/) (`difft` cli)**
  ##### macOS / Linux
  ```
  brew install difftastic
  ```
  **Other:** See other installation options for difftastic [here](https://difftastic.wilfred.me.uk/installation.html).


- **2) Clone / start the local VRL webserver (for testing)**
  ##### Clone
  ```
  git clone https://github.com/shaeqahmed/vrl-web.git
  ```
  ##### Start the server and keep it running (in a new terminal tab)
  ```
  cd vrl-web/vrl-web-server-warp
  cargo run --release
  ```

#### Install dependencies

```
python3 -m pip install -r requirements.txt
```

## Usage

### Example

### Directory sturcture

```python3
examples (an example directory)
└── aws_vpcflow # (create a folder with the logsource name)
    ├── fields # (place files containing ECS / custom fields specified in the Filebeat-style format in this sub directory)
    │   ├── agent.yml
    │   ├── base-fields.yml
    │   ├── ecs.yml
    │   └── fields.yml
    ├── log_source.yml # (the edited log source file)
    ├── log_source_generated.yml.go  # (the generated log source file, use this to update^)
    └── test # (directory containing test + expected files, also according to the Filebeat style (e.g. '-expected.json' for assertions)
        ├── test-extra-samples.log
        ├── test-extra-samples.log-expected.json
        ├── test-tcp-flag-sequence.log
        ├── test-tcp-flag-sequence.log-expected.json
        ├── test-v5-all-fields.log
        ├── test-v5-all-fields.log-expected.json
        ├── test-with-message-field.log
        └── test-with-message-field.log-expected.json
```

### Running the CLI

```bash
python3 main.py --logsource-dir examples/minimal # simple working example

python3 main.py --logsource-dir examples/aws_vpcflow # example for devloping a new log source for AWS VPC Flow logs using an existing test case suite / schema
```

Running this command will help you create a valid `log_source.yml` file for a log source name `aws_vpcflow`. It will use the fields (schema) and tests you have provided in the `fields/` and `test/` subdirectories respectively.

For inspiration on example test cases, fields to start with, and how to structure ECS compatible tables, you can reference the approach from Filebeat / Elastic e.g.:  

##### Log source https://github.com/elastic/integrations/tree/main/packages/aws/data_stream/vpcflow
- ##### Tests https://github.com/elastic/integrations/tree/main/packages/aws/data_stream/vpcflow/_dev/test/pipeline
- ##### Fields https://github.com/elastic/integrations/tree/main/packages/aws/data_stream/vpcflow/fields

## Development Workflow

After running the script, if an error is encountered such as an invalid VRL script, mismatching schemas, etc. the error will be logged by the CLI and your EDITOR will be opened with the corresponding files (log source, failing test case, etc.) prompting you to make the necessary fixes.

Once you have made the fixes, close the editor window, and **hit 'enter** in the CLI as it prompts you to re-run the steps until all the test cases are passing. To close out the interactive session, run **Ctrl + C** in the terminal to end the process.

Happy log source writing 🎉. 
