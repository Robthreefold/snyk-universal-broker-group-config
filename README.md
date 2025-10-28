# Universal Broker Mass Integration

A Python tool for mass configuring Snyk organizations with broker connections.

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd universal-broker-mass-integrate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Configuration

Configure broker for all organizations in a group:

```bash
python3 broker_mass_configure.py \
  --snyk-token $SNYK_TOKEN \
  --group-id $GROUP_ID \
  --source-org-id ef49fa76-2563-4dcb-8195-542ddaa91422 \
  --tenant-id $TENANT_ID
```

### Dry Run Mode

Test the configuration without making changes:

```bash
python3 broker_mass_configure.py \
  --snyk-token $SNYK_TOKEN \
  --group-id $GROUP_ID \
  --source-org-id ef49fa76-2563-4dcb-8195-542ddaa91422 \
  --tenant-id $TENANT_ID \
  --dry-run
```

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
python3 broker_mass_configure.py \
  --snyk-token $SNYK_TOKEN \
  --group-id $GROUP_ID \
  --source-org-id ef49fa76-2563-4dcb-8195-542ddaa91422 \
  --tenant-id $TENANT_ID \
  --debug
```

### Combined Options

Run with both dry-run and debug:

```bash
python3 broker_mass_configure.py \
  --snyk-token $SNYK_TOKEN \
  --group-id $GROUP_ID \
  --source-org-id ef49fa76-2563-4dcb-8195-542ddaa91422 \
  --tenant-id $TENANT_ID \
  --dry-run \
  --debug
```

### Remove a Connection Across All Orgs in a Group

Remove a specific broker connection from all organizations in a group (supports dry run). `--source-org-id` is not required for removal:

```bash
python3 broker_mass_configure.py \
  --snyk-token $SNYK_TOKEN \
  --tenant-id $TENANT_ID \
  --group-id $GROUP_ID \
  --remove-connection <CONNECTION_ID> \
  --dry-run  # optional
```

Notes:
- `--dry-run` will only report what would be removed without deleting anything.

## Arguments

- `--snyk-token`: Your Snyk API token (required)
- `--group-id`: Snyk group ID containing the organizations (required)
- `--source-org-id`: Source organization ID with the broker configuration (required)
- `--tenant-id`: Snyk tenant ID (required)
- `--broker-connection-id`: Specific broker connection ID (optional)
- `--dry-run`: Test mode - shows what would be configured without making changes
- `--debug`: Enable detailed debug logging

## How It Works

1. **Fetches all organizations** in the specified group
2. **Identifies the source organization's** broker configuration
3. **Deletes existing broker configurations** for all target organizations
4. **Applies the source organization's broker configuration** to all target organizations

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.