# macOS Update Processor
__Keep your macOS devices up to date using Declarative Device Management, Jamf Pro, and a SOFA feed.__

## Overview

Let's be real. Keeping macOS devices up to date at scale isn't fun. I know I'm not the only one still occasionally pining for the days of sending `softwareupdate -aiR` over ARD and calling it a day. Unfortunately, those days are gone. Fortunately, this can get close!

Given appropriate API credentials to your jamf tenant, this script will find outdated devices, ensure they're eligible for DDM-based update enforcement, and handle all the dirty work for you.

## Requirements
In order for this script to run successfully, you'll need the following:
- Jamf Pro v11.9.1 or later
- API Credentials for your jamf tenant with the following permissions:
  - Read Computers
  - Create/Read/Update/Delete Managed Software Updates
  - Read Smart Computer Groups
  - Read Static Computer Groups
  - Send Computer Remote Command to Download and Install OS X Update
- Python v3.12 or later (3.10+ may work, but only tested on 3.12)
- Additional modules detailed in requirements.txt -- I suggest the "recommended" flavor of MacAdmins Python: https://github.com/macadmins/python
  - This recommended Python package also includes any other modules this script requires ***(EXCEPT for jamf-pro-sdk)***
  - Be sure to update the shebang to point to your managed installation

## Acknowledgements

Big thanks to the creators and maintainers of SOFA (https://sofa.macadmins.io/), without whom this project would not be possible

## Known Issues/Deficiencies

- This script is currently hardcoded for macOS updates only. It could be modified to also support updating iOS devices. I may do this in the future, but it is not currently planned.
- The sendNotifications function is planned but not currently implemented.
- The `--check` and `--retry` arguments have not been tested and may not be functional. Use at your own risk.
- Canary --> general deployment flows have not been tested and may not be functional. Use at your own risk.

## Usage

### I don't want to read docs. Just tell me how to make it go.
The only required arguments are your jamf URL and credentials. This will YOLO the shiniest release from Cupertino to all eligible devices.

With that said, I recommend at least checking out the `--targetversion` argument for a bit more control.

### Arguments

__REQUIRED__
- `--jamfurl`: URL for the target jamf instance -- protocol prefix not required (ex: org.jamfcloud.com)
- `--clientid`: Jamf Pro API Client ID
- `--clientsecret`: Jamf Pro API Client Secret

__OPTIONAL__

_Prior Run Metadata Handling_
- `--check`: Read existing plan data from file and update with the latest results
- `--retry`: After checking existing plan data, retry any failed plans. Use of this option implies --check.
**CAUTION**: Retries will re-use existing installation deadlines. This could result in devices restarting for updates with little to no warning.
Retries for exceeded installation deadlines will receive a new deadline of 3 days.

_CVE Checking_
- `--nvdtoken`: API key for NIST NVD. Not required, but providing one will enable faster CVE processing due to higher rate limits.
**NOTE**: Using VulnCheck is strongly recommended over NVD due to ongoing issues with NIST update timeliness.
- `--vulnchecktoken`: API key for VulnCheck (https://vulncheck.com)

_SOFA Options_
- `--feedsource`: Full path or URL to a SOFA-generated macos_data_feed.json file. Defaults to https://sofafeed.macadmins.io/v1/macos_data_feed.json
- `--timestamp`: Full path or URL to a SOFA-generated timestamp.json file. Defaults to https://sofafeed.macadmins.io/v1/timestamp.json

_Target macOS Version_
- `--targetversion`: Target macOS version for deployment. Can be any of the following:

  - Specific Version -- A specific macOS version to target for ALL eligible devices (e.g. 14.7.1) | Use --overridegroup and/or --excludegroup to target subsets of devices
  - "ANY" (default)  -- The latest and greatest Cupertino has to offer for ALL eligible devices
  - "MAJOR"          -- Target ONLY devices running the latest major version of macOS (e.g. updates devices on macOS 15 to the latest release of macOS 15)
  - "MINOR"          -- Target devices running the 2 latest major versions of macOS for their respective latest releases (e.g. 14.x to latest 14 and 15.x to latest 15)

_Device Scoping Options_
- `--excludegroup`: Name of a Smart/Static Computer Group containing devices to EXCLUDE from automated updates (such as conference room devices)
- `--overridegroup`: Name of a Smart/Static Computer Group to target for updates (overrides default outdated group)
- `--canarygroup`: Name of a Smart/Static Computer Group containing devices to always receive a 2-day installation deadline.
**NOTE**: Canary deployments are __NOT__ currently compatible with --targetversion "MINOR".

_Canary Deployment Options_
- `--canaryversion`: macOS ProductVersion deployed to canary group. Used to ensure the same version is deployed fleetwide.
- `--canaryok`: Deploy macOS update fleetwide, assuming successful canary deployment

_Deadline Options_
- `--canarydeadline`: Number of days before deadline for the canary group (Default: 2)
- `--urgentdeadline`: Force the update to all outdated devices with the specified deadline (in days), if the aggregate CVE scores warrant accelerated deployment (Default: 7)
- `--deadline`: Force the update to all outdated devices with the specified deadline (in days) (Default: 14)
- __Not Implemented__ `--force`: Force the update to all outdated devices with the specified deadline (in days), overriding any configured canary data

_Other Arguments_
- `--debug`: Enable debug logging for this script
- `--dryrun`: Output proposed actions without executing any changes
- `--datafile`: Full path or filename for storing plan data (defaults to current working directory)
- `--version`: Show script version and exit

### Examples

_All examples below assume jamf url and credentials arguments are also provided_

`--targetversion MAJOR --excludegroup "Zoom Room Devices"`: Dynamically determines an installation deadline based on CVE data in the latest macOS release, and sends DDM update plans to all devices running the latest major version of macOS, except for devices in the "Zoom Room Devices" group

`--targetversion 14.7.1 --overridegroup "Conference Rooms" --deadline 4`: Finds all devices not running at least macOS 14.7.1 that are also in the "Conferece Rooms" group, and sends DDM update plans to those devices with a 4 day deadline

`--targetversion MINOR --deadline 21 --dryrun`: Determines the latest releases of both the current and prior major macOS versions, and sends DDM update plans with a 21 day deadline to eligible devices according to their current major version (e.g. devices will not be upgraded from one major version to the next)
This example also includes the `--dryrun` argument, which will only output what _would_ be deployed, but no update plans will actually be created.

## How It Works

When run, this script does the following:
- Validates that DDM updates are enabled in your jamf instance
- Parses and validates SOFA feed data
- Based on provided arguments, determines target macOS version(s)
- Ensures jamf is aware of the target version(s) and offers them for deployment
- If a custom deadline has _not_ been configured, CVEs patched in the target macOS version(s) are checked for their impact and exploitability scores. All scores are averaged.
  - If the average exploitability score is greater than 6, OR
  - The average impact score is greater than 8, THEN
  - The installation deadline is set to the value of `--urgentdeadline` (Default: 7)
- Finds devices in-scope for the target macOS version(s), and filters the list further if any group arguments are specified
- Checks target devices for DDM update eligibility. A device is eligible if ALL of the following are true:
  - The device must have DDM enabled (General > Declarative Device Management Enabled)
  - The device must have an escrowed bootstrap token (Security > Bootstrap Token Escrowed)
  - The device must be running macOS Sonoma (14) or later (Operating System > Version)
  - The device must support the target macOS version (Operating System > Software Update Device ID)
- Checks target devices for any existing update plans in progress
  - As of Dec 3, 2024, jamf does not offer the ability to cancel individual update plans, even if they've appeared to fail (such as an installation deadline exceeded). Instead, the DDM update functionality must be completely disabled and re-enabled to clear existing plans, which clears ALL existing plans. I'd really appreciate an upvote on feature request [JPRO-I-336](https://ideas.jamf.com/ideas/JPRO-I-336) so we can get this functionality!
  - Because of the above, devices with plans in progress cannot have new plans sent to them
- Finally, sends the update plans to in-scope eligible devices, verifies their successful (or not) deployment, and outputs a run summary

### Installation Deadlines

While jamf has the ability to send macOS updates with deferrals instead of a deadline date and time, I didn't include that functionality. If you'd like to see it, please open an issue (or comment/upvote if one already exists).

The same is true for the Download > Install > Restart method. I'm more likely to build this option at some point, but it's not currently planned.

Deadlines are specified in a number of days (relative to the current date). Work is planned to use either a relative deadline or days since target version release.

**Good to Know**
- Installation deadlines are hardcoded for 7PM on the deadline date. This time is local to the device, so no need to worry about accounting for time zones!
- If a configured deadline falls on a weekend day (Saturday or Sunday), it is automatically extended to the following Monday.
- It is not currently possible to specify a deadline of `0` days.

## User Experience
The great thing about using DDM for macOS update enforcement is that anything user-facing is strictly native macOS behavior.

Apple's [Platform Deployment Guide](https://support.apple.com/guide/deployment/installing-and-enforcing-software-updates-depd30715cbb/1/web/1.0) has a great overview of what users should expect to see when DDM update declarations have been sent to their device. Check out the `Enforcing software updates` section for a really useful flowchart detailing when and how often users are notified about an upcoming deadline.

## Bugs and Feature Requests

For any issues encountered or feature requests, please open an issue.

Pull requests are also welcome for both of the above.

### Reminder

This repo is licensed under an MIT license. Please review the [`LICENSE`](https://github.com/mhrono/jamf-sofa-processor/blob/main/LICENSE) carefully before using this script.
