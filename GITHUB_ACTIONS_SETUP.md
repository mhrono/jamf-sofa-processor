# GitHub Actions Setup Guide

This guide explains how to set up and customize the example GitHub Actions workflow for automated macOS update deployments using `macos-update-processor.py`.

## Overview

The example workflow (`example-macos-update-deployment.yml`) provides:
- Automated SOFA feed monitoring
- Canary deployment support
- Scheduled and manual deployment triggers
- Dry run and debug modes
- Metadata caching for deployment tracking

**Security Note:** The example workflow uses pinned GitHub Actions with SHA hashes (e.g., `actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8`) instead of version tags. This prevents supply chain attacks where action maintainers could update a tagged version maliciously. The workflow also uses `zsh` as the shell for consistency and improved string handling.

## Prerequisites

1. **Jamf Pro Environment**
   - Jamf Pro instance with API access
   - API Client with appropriate permissions (DDM, computers, groups)
   - Declarative Device Management (DDM) enabled

2. **GitHub Repository Setup**
   - Repository containing `macos-update-processor.py` and `requirements.txt`
   - GitHub Actions enabled

## Configuration Steps

### 1. Set Up Repository Secrets

Add the following secrets to your GitHub repository (Settings → Secrets and variables → Actions):

| Secret Name | Description | Example |
|-------------|-------------|---------|
| `JAMF_CLIENT_ID` | Jamf Pro API Client ID | `abc123-def456-ghi789` |
| `JAMF_CLIENT_SECRET` | Jamf Pro API Client Secret | `********************************` |

**Optional secrets for notifications/integrations:**
- `SLACK_WEBHOOK_URL` - For Slack notifications
- `SLACK_TOKEN` - For Slack user lookups (@mentions)

### 2. Set Up Repository Variables

Add the following variables to your repository (Settings → Secrets and variables → Actions → Variables):

| Variable Name | Description | Example |
|---------------|-------------|---------|
| `JAMF_URL` | Your Jamf Pro URL | `https://yourcompany.jamfcloud.com` |

### 3. Customize the Workflow

Open `.github/workflows/example-macos-update-deployment.yml` and customize these sections:

#### Schedule (Line 54)
Adjust the cron schedule for your needs:
```yaml
schedule:
  - cron: '0 */6 * * *'  # Every 6 hours
```

#### Scheduled Run Defaults (Lines 157-161)
Set your organization's default exclude/canary groups:
```yaml
if [[ "${{ github.event_name }}" == "schedule" ]]; then
  scriptArgs+=("--excludegroup" "Conference Room Devices")
  scriptArgs+=("--canarygroup" "Update Test Group")
fi
```

#### Auto-Targeting Logic (Line 71)
Adjust the minor version threshold for "stable" releases:
```yaml
minorVersionThreshold: 3  # .3+ = stable for "any" target
```

For example, with threshold of 3:
- macOS 15.0, 15.1, 15.2 → auto-target "minor" (be conservative)
- macOS 15.3+ → auto-target "any" (considered stable)

#### Script Path (Line 449)
Update the path to your processor script:
```yaml
python3 "${{ github.workspace }}/macos-update-processor.py" ${scriptArgs[@]}
```

#### Post-Deployment Actions (Lines 485-510)
Add your custom reporting/notification logic:
```yaml
- name: Report deployment results
  if: ${{ steps.runProcessor.outputs.runCompleted == 'true' }}
  run: |
    # Your custom logic here
```

### 4. (Optional) Add Notification Support

To enable Slack notifications, modify the script execution step to include notification arguments:

```yaml
- name: Run processor script
  run: |
    scriptArgs="${{ env.scriptArgs }}"
    
    # Add notification arguments
    scriptArgs+=("--notificationtype" "SLACK")
    scriptArgs+=("--notificationurl" "${{ secrets.SLACK_WEBHOOK_URL }}")
    scriptArgs+=("-o" "slack_token=${{ secrets.SLACK_TOKEN }}")
    
    python3 "${{ github.workspace }}/macos-update-processor.py" ${scriptArgs[@]}
```

### 5. (Optional) Multi-Environment Setup

If you have multiple Jamf environments (Dev/Prod), you can:

1. Create GitHub Environments (Settings → Environments):
   - `Production`
   - `Development`

2. Add environment-specific secrets/variables to each environment

3. Add environment selection to workflow inputs:
```yaml
inputs:
  environment:
    description: Target environment
    required: true
    type: environment
    default: 'Development'
```

4. Update the credential step to use environment-specific values:
```yaml
environment: ${{ github.event.inputs.environment }}

steps:
  - name: Set jamf credentials
    run: |
      jamfURL="${{ vars.JAMF_URL }}"
      jamfClientID="${{ secrets.JAMF_CLIENT_ID }}"
      jamfClientSecret="${{ secrets.JAMF_CLIENT_SECRET }}"
      # These now automatically pull from the selected environment
```

## Usage

### Manual Execution

1. Go to Actions tab in your repository
2. Select "Parse and Deploy macOS Updates Using DDM"
3. Click "Run workflow"
4. Configure options:
   - **Operation mode**: What to do (deploy, check, retry, report)
   - **Execution mode**: How to run it (normal, debug, dry_run)
   - **Target macOS version**: Which version to deploy (major, minor, any, or specific)
   - **Groups**: Exclude, override, or canary group names
   - **Force deadline**: Skip canary and force deploy with X day deadline
   - **Canary abort**: Stop in-progress canary deployment
   - **Toggle DDM**: Clear all existing plans (use with caution!)

### Scheduled Execution

The workflow runs automatically based on your cron schedule. It will:
1. Check SOFA feed for new macOS versions
2. Apply auto-targeting logic based on version stability
3. Use default exclude/canary groups configured in the workflow
4. Deploy updates accordingly

### Testing

**Always test first with dry run mode!**

1. Run workflow manually
2. Select "Execution mode: dry_run"
3. Review logs to see what would happen
4. When confident, run in normal mode

## Workflow Logic

### New Version Detection

The workflow compares the current SOFA feed against cached data:
- **New version found** → Trigger deployment
- **Same version, different hash** → Update cache but don't deploy
- **No changes** → Skip run (unless canary deadline passed)

### Canary Deployment Flow

1. **New version detected**:
   - Deploy to canary group with standard deadline
   - Cache deployment metadata

2. **Subsequent runs**:
   - Check if canary deadline has passed
   - If yes → Deploy to all in-scope devices
   - If no → Skip run

3. **Canary abort**:
   - Use "Canary abort" option to stop progression to wide deployment

### Metadata Tracking

The workflow uses GitHub Actions cache to track:
- Deployment metadata (`updatePlanData.json`)
- SOFA feed data (for version comparison)
- Deployment history (canary/standard)

## Troubleshooting

### "No changes detected, skipping run"

This is normal behavior when:
- No new macOS version is available
- Canary deployment is in progress
- Recent deployment already completed

### "Processor run failed"

Check the logs for:
- Authentication errors (check credentials)
- Group not found (verify group names exist in Jamf)
- API rate limiting (adjust schedule frequency)

### Canary not progressing to wide deployment

Verify:
- Canary deadline has passed (`installationDeadlineEpoch`)
- Metadata is being cached correctly
- Check workflow run didn't skip the comparison step

### Cache issues

If metadata seems corrupted:
1. Go to Actions → Caches
2. Delete old caches
3. Run workflow again (will start fresh)

## Advanced Customization

### Custom Deadline Logic

Modify the CVE checking logic in `macos-update-processor.py` to adjust deadline calculation based on vulnerability severity.

### Integration with Monitoring Systems

Add steps to send metrics to your monitoring system:

```yaml
- name: Send metrics
  run: |
    # Example: Send to Datadog, Prometheus, etc.
    curl -X POST "https://api.example.com/metrics" \
      -d "deployment_version=${{ steps.runProcessor.outputs.deployedVersion }}"
```

### Custom Reporting

Generate compliance reports or device inventories:

```yaml
- name: Generate compliance report
  run: |
    # Custom Python script to check device compliance
    python3 generate-compliance-report.py \
      --target-version "${{ steps.runProcessor.outputs.deployedVersion }}"
```

## Security Considerations

- **Never commit secrets** to your repository
- Use GitHub Environments for additional protection rules
- Consider requiring approval for production deployments
- Rotate API credentials regularly
- Use least-privilege API roles in Jamf Pro

## Support

For issues with:
- **The workflow**: Open an issue in this repository
- **The script**: See `README.md` for script-specific documentation
- **Jamf Pro**: Contact Jamf Support
- **SOFA feed**: See [macadmins/sofa](https://github.com/macadmins/sofa)

## Example Scenarios

### Scenario 1: Conservative Deployment
```yaml
# Workflow inputs:
Operation mode: deploy
Execution mode: normal
Target version: minor  # Only latest minor version, not newest major
Exclude group: VIP Devices
Canary group: IT Test Devices
```

### Scenario 2: Emergency Security Update
```yaml
# Workflow inputs:
Operation mode: deploy
Execution mode: normal
Target version: 15.2.1  # Specific security update
Force deadline: 3  # 3 day deadline
Toggle DDM: true  # Clear existing plans to force update
```

### Scenario 3: Testing New Version
```yaml
# Workflow inputs:
Operation mode: deploy
Execution mode: dry_run  # Test first!
Target version: any
Override group: Single Test Device  # Just one device
```

### Scenario 4: Canary Abort
```yaml
# Workflow inputs:
Operation mode: deploy
Canary abort: true  # Stop canary from going wide
```

## Tips

- Start with dry run mode to understand the workflow behavior
- Use debug mode (`execution_mode: debug`) for troubleshooting
- Test canary workflows with short deadlines first (1-2 days)
- Monitor the Actions logs regularly, especially for scheduled runs
- Keep your SOFA cache fresh by running regularly
- Document your organization's deployment policies in the workflow comments

