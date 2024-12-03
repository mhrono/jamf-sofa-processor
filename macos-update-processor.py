#!/usr/bin/env python3

"""
macOS Update Processor
Keep your macOS devices up to date using Declarative Device Management, Jamf Pro, and a SOFA feed.

Author: Matt Hrono @ Chime | MacAdmins: @matt_h | mattonmacs.dev

----
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
----

REQUIREMENTS:

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

ACKNOWLEDGEMENTS:

    Big thanks to the creators and maintainers of SOFA (https://sofa.macadmins.io/), without whom this project would not be possible


OVERVIEW:

    Thanks to GitHub Copilot for this overview and the docstrings in each function


KNOWN ISSUES/DEFICIENCIES:

    - This script is currently hardcoded for macOS updates only. It could be modified to also support updating iOS devices. I may do this in the future, but it is not currently planned.
    - The sendNotifications function is planned but not currently implemented.
    - The --check and --retry arguments have not been tested and may not be functional. Use at your own risk.

This script automates the deployment of macOS updates using Jamf Pro's Declarative Device Management (DDM) capabilities. It fetches the latest macOS version data from a SOFA feed, determines the appropriate installation deadlines based on CVE impact scores, and sends update plans to eligible devices or groups.

Functions:
- check_positive(value): Validates if the provided value is a positive integer.
- check_version_arg(version): Validates the version argument to ensure it matches the expected format.
- check_path(datafile): Checks and resolves the path for the data file.
- endRun(exitCode, logLevel, message): Exits the script with a specified exit code, logging level, and final message.
- loadJson(jsonPath): Loads and returns data from a JSON file.
- dumpJson(jsonData, jsonPath): Dumps data into a JSON file.
- sendNotifications(): Placeholder for sending notifications.
- checkModelSupported(device): Checks if a device is supported for the targeted macOS version.
- getCVEDetails(vulnSource, cveID, requestHeaders): Queries NVD or VulnCheck for details about a specific CVE.
- parseVulns(cveList): Determines whether the update deployment should be accelerated based on CVE impact scores.
- convertJamfTimestamp(timestamp): Converts a millisecond epoch timestamp to a datetime object.
- calculateDeadlineString(deadlineDays): Calculates an installation deadline and returns it in a format acceptable to the Jamf API.
- checkExistingDevicePlans(declarationItem, targetVersion): Checks if there are any active DDM update plans for a given device.
- sendDeclaration(objectType, objectIds, installDeadlineString, osVersion): Sends DDM update plans to a device, a list of devices, or a group.
- getComputerGroupData(groupID, groupName): Returns data about a computer group given its ID or name.
- getVersionData(): Parses the provided SOFA feed for the latest macOS version data.
- determineDeadline(cveList, exploitedCVEs): Determines the installation deadline based on runtime arguments and/or CVE data.
- checkDeploymentAvailable(productVersion): Checks if the target version is available via DDM from Jamf.
- checkDeviceDDMEligible(deviceRecord): Verifies if a device is eligible to receive and process a DDM update.
- getPlanData(planUUID): Retrieves and returns data about an update plan and its status/history.
- deduplicatePlans(planList): Filters a list of update plans to include only the most recently created plan per device.
- retryPlan(plan): Retries a failed update plan.
- run(): Main function to execute the script.

Usage:
- The script can be run with various command-line arguments to specify Jamf Pro credentials, target macOS version, update deadlines, and other options.
- It supports checking and retrying existing update plans, filtering devices by group membership, and performing dry runs without executing any changes.
"""

import argparse
import json
import logging
import os
import re
import time
import sys
import requests
from packaging.version import Version
from pathlib import Path
from datetime import datetime, timedelta, timezone
from tempfile import NamedTemporaryFile

from jamf_pro_sdk import JamfProClient, SessionConfig
from jamf_pro_sdk.models.classic import computer_groups
from jamf_pro_sdk.models.pro import computers
from jamf_pro_sdk.clients.pro_api.pagination import FilterField, filter_group
from jamf_pro_sdk.clients.auth import ApiClientCredentialsProvider

## Version
scriptVersion = "0.4"

## Arguments


## Validate integer inputs for deadlines
def check_positive(value):
    """
    Check if the provided value is a positive integer.

    Args:
        value (str): The value to be checked, expected to be a string representation of an integer.

    Returns:
        int: The integer value if it is positive.

    Raises:
        argparse.ArgumentTypeError: If the value is not a positive integer.
    """
    ivalue = int(value)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
    return ivalue


## Validate input for target version
def check_version_arg(version):
    """
    Validates the version argument to ensure it matches the expected format.

    Args:
        version (str): The version string to validate. It can be one of the following:
                       - "ANY"
                       - "MAJOR"
                       - "MINOR"
                       - A specific macOS version (e.g., "14.6.1" or "15.0")

    Returns:
        str: The validated version string in uppercase.

    Raises:
        argparse.ArgumentTypeError: If the version string does not match the expected format.
    """
    # Regular expression pattern to match version argument
    pattern = (
        r"^any$"  # Matches "any"
        r"|^major$"  # Matches "major"
        r"|^minor$"  # Matches "minor"
        r"|^\d+\.\d+(?:\.\d+)?$"  # Matches specific macOS version (e.g., "14.6.1" or "15.0")
    )

    if re.match(pattern, str(version), re.IGNORECASE):
        return version.upper()
    else:
        raise argparse.ArgumentTypeError(
            f'\nVersion definition must be one of the following:\n\n - ANY\n- MAJOR\n - MINOR\n - Specific macOS Version (e.g. "14.6.1" or "15.0")'
        )


## Validate input for metadata file path
def check_path(datafile):
    """
    Checks and resolves the path for the data file.

    This function takes a path to a data file and determines if it is a directory or a file.
    If it is a directory, it appends "updatePlanData.json" to the directory path.
    If it is a file, it uses the provided file path.
    If neither, it defaults to "updatePlanData.json" in the current working directory.

    Args:
        datafile (str): The path to the data file or directory.

    Returns:
        Path: The resolved path to the data file.

    Raises:
        argparse.ArgumentTypeError: If the path cannot be resolved or the file cannot be created.
    """
    dataDir = Path(datafile).expanduser().resolve()
    pathFail = False

    if dataDir.is_dir():
        filePath = dataDir.joinpath("updatePlanData.json")
    elif Path(datafile).is_file():
        filePath = Path(datafile)
    else:
        filePath = Path.cwd().joinpath("updatePlanData.json")

    try:
        filePath.touch(exist_ok=True)
    except:
        pathFail = True

    if not filePath.exists() or pathFail:
        raise argparse.ArgumentTypeError(
            "Unable to parse data file path. Please try again or leave blank to use the default location (current working directory)"
        )
    else:
        return filePath


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    argument_default=argparse.SUPPRESS,
)

parser.add_argument(
    "--jamfurl",
    nargs="?",
    help="URL for the target jamf instance -- protocol prefix not required (ex: org.jamfcloud.com)",
)

parser.add_argument("--clientid", nargs="?", help="Jamf Pro API Client ID")

parser.add_argument("--clientsecret", nargs="?", help="Jamf Pro API Client Secret")

parser.add_argument(
    "--check",
    action="store_true",
    help="Read existing plan data from file and update with the latest results",
)

parser.add_argument(
    "--retry",
    action="store_true",
    help="After checking existing plan data, retry any failed plans. Use of this option implies --check.\n\nCAUTION: Retries will re-use existing installation deadlines. This could result in devices restarting for updates with little to no warning.\nRetries for exceeded installation deadlines will receive a new deadline of 3 days.",
)

parser.add_argument(
    "--nvdtoken",
    nargs="?",
    metavar="token",
    help="API key for NIST NVD. Not required, but providing one will enable faster CVE processing due to higher rate limits. NOTE: Using VulnCheck is strongly recommended over NVD due to ongoing issues with NIST update timeliness.",
)

parser.add_argument(
    "--vulnchecktoken",
    nargs="?",
    metavar="token",
    help="API key for VulnCheck (https://vulncheck.com)",
)

parser.add_argument(
    "--feedsource",
    default="https://sofafeed.macadmins.io/v1/macos_data_feed.json?",
    const="https://sofafeed.macadmins.io/v1/macos_data_feed.json?",
    nargs="?",
    metavar="URL or path",
    help="Full path or URL to a SOFA-generated macos_data_feed.json file. Defaults to https://sofafeed.macadmins.io/v1/macos_data_feed.json",
)

parser.add_argument(
    "--timestamp",
    default="https://sofafeed.macadmins.io/v1/timestamp.json?",
    const="https://sofafeed.macadmins.io/v1/timestamp.json?",
    nargs="?",
    metavar="URL or path",
    help="Full path or URL to a SOFA-generated timestamp.json file. Defaults to https://sofafeed.macadmins.io/v1/timestamp.json",
)

parser.add_argument(
    "--targetversion",
    default="ANY",
    const="ANY",
    nargs="?",
    type=check_version_arg,
    metavar="Version (string or type)",
    help="""Target macOS version for deployment. Can be any of the following:

- Specific Version -- A specific macOS version to target for ALL eligible devices (e.g. 14.7.1) | Use --overridegroup and/or --excludegroup to target subsets of devices
- "ANY" (default)  -- The latest and greatest Cupertino has to offer for ALL eligible devices
- "MAJOR"          -- Target ONLY devices running the latest major version of macOS (e.g. updates devices on macOS 15 to the latest release of macOS 15)
- "MINOR"          -- Target devices running the 2 latest major versions of macOS for their respective latest releases (e.g. 14.x to latest 14 and 15.x to latest 15)""",
)

parser.add_argument(
    "--excludegroup",
    nargs="+",
    metavar="Excluded Group Name",
    help="Name of a Smart/Static Computer Group containing devices to EXCLUDE from automated updates (such as conference room devices)",
)

parser.add_argument(
    "--overridegroup",
    nargs="+",
    metavar="Override Group Name",
    help="Name of a Smart/Static Computer Group to target for updates (overrides default outdated group)",
)

parser.add_argument(
    "--canarygroup",
    nargs="+",
    metavar="Canary Group Name",
    help='Name of a Smart/Static Computer Group containing devices to always receive a 2-day installation deadline.\n\nNOTE: Canary deployments are NOT currently compatible with --targetversion "MINOR".',
)

parser.add_argument(
    "--canaryversion",
    nargs="?",
    metavar="macOS Version",
    help="macOS ProductVersion deployed to canary group. Used to ensure the same version is deployed fleetwide.",
)

parser.add_argument(
    "--canaryok",
    action="store_true",
    help="Deploy macOS update fleetwide, assuming successful canary deployment",
)

parser.add_argument(
    "--canarydeadline",
    default=2,
    const=2,
    nargs="?",
    type=check_positive,
    metavar="Days until deadline",
    help="Number of days before deadline for the canary group",
)

parser.add_argument(
    "--urgentdeadline",
    default=7,
    const=7,
    nargs="?",
    type=check_positive,
    metavar="Days until deadline",
    help="Force the update to all outdated devices with the specified deadline (in days), if the aggregate CVE scores warrant accelerated deployment",
)

parser.add_argument(
    "--deadline",
    default=14,
    const=14,
    nargs="?",
    type=check_positive,
    metavar="Days until deadline",
    help="Force the update to all outdated devices with the specified deadline (in days)",
)

parser.add_argument(
    "--force",
    nargs="?",
    type=check_positive,
    metavar="Days until deadline",
    help="Force the update to all outdated devices with the specified deadline (in days), overriding any configured canary data",
)

parser.add_argument(
    "--debug",
    action="store_true",
    help="Enable debug logging for this script",
)
parser.add_argument(
    "--dryrun",
    action="store_true",
    help="Output proposed actions without executing any changes",
)

parser.add_argument(
    "--datafile",
    nargs="?",
    type=check_path,
    metavar="Path or filename",
    help="Full path or filename for storing plan data",
)

parser.add_argument(
    "--version",
    action="version",
    version=f"{scriptVersion}",
    help="Show script version and exit",
)

args = parser.parse_args()

jamfURL = args.jamfurl if "jamfurl" in args else os.environ.get("jamfURL", None)
jamfClientID = (
    args.clientid if "clientid" in args else os.environ.get("jamfClientID", None)
)
jamfClientSecret = (
    args.clientsecret
    if "clientsecret" in args
    else os.environ.get("jamfClientSecret", None)
)

checkPlans = args.check if "check" in args else None
retryPlans = args.retry if "retry" in args else None

nvdToken = args.nvdtoken if "nvdtoken" in args else os.environ.get("nvdToken", None)
vulncheckToken = (
    args.vulnchecktoken
    if "vulnchecktoken" in args
    else os.environ.get("vulncheckToken", None)
)

excludedGroupName = " ".join(args.excludegroup) if "excludegroup" in args else None
overrideGroupName = " ".join(args.overridegroup) if "overridegroup" in args else None

targetVersionType = args.targetversion.upper()

canaryGroupName = " ".join(args.canarygroup) if "canarygroup" in args else None
canaryVersion = args.canaryversion.replace('"', "") if "canaryversion" in args else None
canaryOK = args.canaryok if "canaryok" in args else False

canaryDays = args.canarydeadline
urgentDays = args.urgentdeadline
standardDays = args.deadline

customDeadline = True if "deadline" in args and args.deadline != 14 else False

forceDays = args.force if "force" in args else None

dataFilePath = (
    Path(args.datafile)
    if "datafile" in args
    else Path.cwd().joinpath("updatePlanData.json")
)

debug = args.debug if "debug" in args else None
dryrun = args.dryrun if "dryrun" in args else False

###############################
#### Logging configuration ####
###############################

## Local log file
logFile = NamedTemporaryFile(
    prefix="jamf-ddm-deploy_",
    suffix=f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.log",
    delete=False,
    dir=Path.cwd(),
).name

## Configure root logger
logger = logging.getLogger()
logger.handlers = []

## Create handlers
logToFile = logging.FileHandler(str(logFile))
jamfLogToFile = logging.FileHandler(str(logFile))
logToConsole = logging.StreamHandler(sys.stdout)
jamfLogToConsole = logging.StreamHandler(sys.stdout)

## Configure logging level and format
logLevel = logging.DEBUG if debug else logging.INFO
logFormat = logging.Formatter(
    "[%(asctime)s %(filename)s->%(funcName)s():%(lineno)s]%(levelname)s: %(message)s"
    if debug
    else "%(asctime)s [%(levelname)s] %(message)s"
)

## Set root and handler logging levels
logger.setLevel(logLevel)
logToFile.setLevel(logLevel)
logToConsole.setLevel(logLevel)

## Set log format
logToFile.setFormatter(logFormat)
jamfLogToFile.setFormatter(logFormat)
logToConsole.setFormatter(logFormat)
jamfLogToConsole.setFormatter(logFormat)

## Configure jamf SDK logging
jamfLogger = logging.getLogger("jamf_pro_sdk")
jamfLogLevel = logging.DEBUG if debug else logging.WARNING
jamfLogger.setLevel(jamfLogLevel)

## Add handlers to jamf logger
jamfLogger.addHandler(jamfLogToFile)
jamfLogger.addHandler(jamfLogToConsole)

## Add handlers to root logger
logger.addHandler(logToFile)
logger.addHandler(logToConsole)

###############################


## Exit with a specified exit code, logging level, and final message
def endRun(exitCode=None, logLevel="info", message=None):
    """
    Terminates the program with a specified exit code and logs a message.

    Args:
        exitCode (int, optional): The exit code to terminate the program with. Defaults to None.
        logLevel (str, optional): The logging level for the message. Defaults to "info".
        message (str, optional): The message to log. Defaults to None.

    Raises:
        SystemExit: Exits the program with the specified exit code.
    """

    logCmd = getattr(logging, logLevel, "info")
    logCmd = getattr(logging, logLevel, logging.info)
    if message:
        logCmd(message)
    sys.exit(exitCode)


## Load feed file
if feedSource := args.feedsource:
    logging.debug(f"Attempting to fetch macOS data feed from {feedSource}...")

    try:
        if feedSource.startswith("http://") or feedSource.startswith("https://"):
            feedData = json.loads(requests.get(feedSource).content)

        elif Path(feedSource).exists():
            feedData = json.loads(Path(feedSource).read_text())
    except json.JSONDecodeError as e:
        endRun(1, "critical", f"Failed to decode JSON from {feedSource}: {e}")
    except:
        endRun(1, "critical", f"Failed to fetch feed data from {feedSource}, exiting!")

else:
    endRun(1, "critical", "Unknown issue encountered fetching feed data, exiting...")

## Load timestamp data
if timestampSource := args.timestamp:
    logging.debug(
        f"Attempting to fetch SOFA feed timestamp data from {timestampSource}..."
    )

    try:
        if timestampSource.startswith("http://") or timestampSource.startswith(
            "https://"
        ):
            timestampData = json.loads(requests.get(timestampSource).content)

        elif Path(timestampSource).exists():
            timestampData = json.loads(Path(timestampSource).read_text())

        logging.debug("Successfully retrieved timestamp data")

    except:
        endRun(
            1,
            "critical",
            f"Failed to fetch timestamp data from {timestampSource}, exiting!",
        )

else:
    endRun(
        1, "critical", "Unknown issue encountered fetching timestamp data, exiting..."
    )


## Load and return data from a json file
def loadJson(jsonPath):
    """
    Parameters:
    jsonPath (Path): The path to the JSON file to be loaded.

    Returns:
    dict: The data loaded from the JSON file.
    """
    logging.debug(f"Loading json data from {str(jsonPath)}")
    try:
        jsonData = json.loads(jsonPath.read_text())
        return jsonData
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {str(jsonPath)}: {e}")
        return None


## Dump data into a json file
def dumpJson(jsonData, jsonPath):
    """
    Dump data into a JSON file.

    Parameters:
    jsonData (dict): The data to be written to the JSON file.
    jsonPath (Path): The path to the JSON file where the data will be written.
    """
    logging.debug(f"Dumping json data to {str(jsonPath)}")
    logging.debug(f"json data sent: {jsonData}")
    jsonPath.write_text(json.dumps(jsonData, indent=4, separators=(",", ": ")))


## TODO: Notify a Slack channel, Okta Workflow, or some other webhook when a deployment happens
def sendNotifications():
    pass


## Make sure a device is supported for the targeted version before sending a declaration
def checkModelSupported(device):
    """
    Checks if the given device model is supported for the target macOS version.

    Args:
        device (object): The device object containing information about the device, including its operating system and software update device ID.

    Returns:
        bool: True if the device model is supported for the target macOS version, False otherwise.

    Logs:
        A warning message if the device model is not supported for the target macOS version.
    """
    global targetVersionSupportedDevices

    swuDeviceID = device.operatingSystem.softwareUpdateDeviceId

    if swuDeviceID not in targetVersionSupportedDevices:
        logging.warning(
            f"Device {device.id} does not support the target macOS version!"
        )
    return swuDeviceID in targetVersionSupportedDevices


## Query NVD or VulnCheck for details about a specific CVE
def getCVEDetails(vulnSource, cveID, requestHeaders):
    """
    Retrieve details for a given CVE ID from the specified vulnerability source.

    Args:
        vulnSource (str): The source to check for CVE details. Valid values are "vulncheck" and "NVD".
        cveID (str): The CVE ID to retrieve details for.
        requestHeaders (dict): Headers to include in the request.

    Returns:
        dict: A dictionary containing CVE details including 'id', 'description', 'exploitabilityScore', and 'impactScore'.
        None: If no CVE ID is provided, the CVE ID is invalid, or no results are found.

    Raises:
        None

    Logs:
        Various debug, error, and warning messages to indicate the progress and any issues encountered.
    """

    if not cveID:
        logging.error("No CVE ID provided, unable to get details")
        return None

    if not re.match(r"^CVE-\d{4}-\d+$", cveID, re.IGNORECASE):
        logging.error(f"{cveID} does not appear to be a valid CVE ID!")
        return None

    if vulnSource == "vulncheck":
        checkURL = "https://api.vulncheck.com/v3/index/nist-nvd2?cve="

    else:
        vulnSource = "NVD"
        checkURL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

    logging.debug(f"Checking {vulnSource} for details on CVE {cveID}...")
    cveCheckResponse = requests.get(checkURL + cveID, headers=requestHeaders)

    if not cveCheckResponse.ok:
        logging.error(
            f"Error occured checking for CVE details. Received return code {cveCheckResponse.status_code}"
        )
        return None

    else:
        logging.debug("Successfully retrieved CVE data")
        cveResponseContent = cveCheckResponse.json()

    if (
        cveResponseContent.get("totalResults") == 0
        or vulnSource == "vulncheck"
        and cveResponseContent.get("_meta").get("total_documents") == 0
    ):
        logging.warning(f"No results found for CVE ID {cveID}")
        return None

    if vulnSource == "vulncheck":
        cveData = cveResponseContent.get("data")[0]

    else:
        cveData = cveResponseContent.get("vulnerabilities")[0].get("cve")

    if cveMetrics := cveData.get("metrics"):
        cveMetricsData = cveMetrics.get(list(cveData.get("metrics").keys())[0])[0]

    else:
        cveMetricsData = {}

    exploitabilityScore = cveMetricsData.get("exploitabilityScore", 0)
    impactScore = cveMetricsData.get("impactScore", 0)

    cveDetails = {
        "id": cveID,
        "description": next(
            i.get("value") for i in cveData.get("descriptions") if i.get("lang") == "en"
        ),
        "exploitabilityScore": exploitabilityScore,
        "impactScore": impactScore,
    }

    logging.debug(f"CVE data: {cveDetails}")
    return cveDetails


## Given a list of CVEs patched in a macOS release, determine whether or not the update deployment should be accelerated based on their impact scores
def parseVulns(cveList):
    """
    Parses a list of CVEs and calculates the average exploitability and impact scores.

    This function retrieves CVE details from either the NVD or VulnCheck API, calculates the
    average exploitability and impact scores, and determines if the scores exceed predefined
    risk thresholds.

    Args:
        cveList (list): A list of CVE identifiers to be processed.

    Returns:
        bool: True if the average scores exceed the risk thresholds, indicating a need for a
              shorter installation deadline. False otherwise.
    """

    logging.info("Calculating average CVE impact score for this release...")

    cveCount = len(cveList)
    totalExploitabilityScore = 0
    totalImpactScore = 0

    requestHeaders = {"accept": "application/json"}

    vulnSource = "nvd"

    if not any([nvdToken, vulncheckToken]):
        logging.debug(
            "No NVD or VulnCheck API tokens found, using NVD with public unauthenticated rate limits"
        )
        standoffTime = 7

    elif vulncheckToken:
        logging.debug("Using VulnCheck API token with no rate limits")
        vulnSource = "vulncheck"
        standoffTime = 0

        requestHeaders.update({"Authorization": f"Bearer {vulncheckToken}"})

    elif nvdToken:
        logging.debug("Using NVD API token for higher rate limits")
        standoffTime = 0.75

        requestHeaders.update({"apiKey": nvdToken})

    for cve in cveList:
        exploitabilityScore = None
        impactScore = None
        if cveData := getCVEDetails(vulnSource, cve, requestHeaders):

            exploitabilityScore = cveData.get("exploitabilityScore", None)
            impactScore = cveData.get("impactScore", None)

        if not cveData:
            logging.warning(
                f"No CVE metrics found for {cve}, excluding from average calculation"
            )
            cveCount -= 1

        else:
            logging.debug(
                f"CVE {cve}: Exploitability = {exploitabilityScore}, Impact = {impactScore}"
            )
        if cveData:
            totalExploitabilityScore += exploitabilityScore
            totalImpactScore += impactScore
        totalExploitabilityScore += exploitabilityScore
        totalImpactScore += impactScore

        if standoffTime > 0:
            logging.debug(f"Waiting {standoffTime} seconds before next request...")
            time.sleep(standoffTime)
    if cveCount > 0:
        averageExploitabilityScore = round(totalExploitabilityScore / cveCount, 1)
        if cveCount > 0:
            averageExploitabilityScore = round(totalExploitabilityScore / cveCount, 1)
            averageImpactScore = round(totalImpactScore / cveCount, 1)
        else:
            averageExploitabilityScore = 0
            averageImpactScore = 0

        logging.debug(f"Average exploitability score: {averageExploitabilityScore}")
        logging.debug(f"Average impact score: {averageImpactScore}")

        if averageExploitabilityScore > 6:
            logging.info(
                f"Average exploitability score {averageExploitabilityScore} exceeds the threshold of 6--forcing shorter installation deadline!"
            )
            return True
        elif averageImpactScore > 8:
            logging.info(
                f"Average impact score {averageImpactScore} exceeds the threshold of 8--forcing shorter installation deadline!"
            )
            return True
        else:
            logging.info(
                "Average exploitability and impact scores are within normal risk ranges. No accelerated deadline required."
            )
            return False
    else:
        logging.debug(f"Average exploitability score: {averageExploitabilityScore}")
        logging.debug(f"Average impact score: {averageImpactScore}")

    EXPLOITABILITY_THRESHOLD = 6
    IMPACT_THRESHOLD = 8

    if (
        averageExploitabilityScore > EXPLOITABILITY_THRESHOLD
        or averageImpactScore > IMPACT_THRESHOLD
    ):
        logging.info(
            f"Average scores have tripped the risk threshold--forcing shorter installation deadline!"
        )
        return True

    else:
        logging.info(
            "Average exploitability and impact scores are within normal risk ranges. No accelerated deadline required."
        )
        return False


## Convert a millisecond epoch timestamp received from the jamf api to a datetime object
def convertJamfTimestamp(timestamp):
    """
    Converts a Jamf timestamp (in milliseconds) to a dictionary containing the epoch time (in seconds)
    and a datetime object.

    Args:
        timestamp (int): The Jamf timestamp in milliseconds.

    Returns:
        dict: A dictionary with the following keys:
            - "epochTime" (int): The epoch time in seconds.
            - "datetime" (datetime): The corresponding datetime object.

    Raises:
        ValueError: If the timestamp is missing or malformed.
    """

    if not timestamp or not check_positive(str(timestamp)):
        logging.error("Timestamp missing or malformed--cannot convert!")
        return None

    timestampSeconds = round(timestamp / 1000)
    timeObject = datetime.fromtimestamp(timestampSeconds)

    timeData = (
        {"epochTime": timestampSeconds, "datetime": timeObject}
        if isinstance(timestampSeconds, int)
        else None
    )

    logging.debug(
        f"Converted timestamp {timestamp} to {timeObject.strftime("%Y-%m-%dT%H:%M:%S")} (epoch: {timestampSeconds})"
    )

    return timeData


## Given an integer, calculate an installation deadline and return it in a format acceptable to the jamf API
def calculateDeadlineString(deadlineDays):
    """
    Calculate the installation deadline string based on the given number of days.

    This function calculates a deadline date by adding the specified number of days
    to the current date. If the calculated deadline falls on a weekend (Saturday or Sunday),
    it adjusts the deadline to the following Monday. The final deadline is formatted
    as an ISO 8601 string with a fixed time of 19:00:00.

    Args:
        deadlineDays (int): The number of days from the current date to set the deadline.
                            If the value is missing or not positive, a default of 7 days is used.

    Returns:
        str: The calculated deadline date as an ISO 8601 formatted string.
    """

    if not deadlineDays or not check_positive(str(deadlineDays)):
        logging.error("Deadline missing or malformed--defaulting to 7 days")
        deadlineDays = 7

    deadlineDate = datetime.now() + timedelta(days=deadlineDays)

    if deadlineDate.isoweekday() in {6, 7}:
        logging.info(
            "Configured deadline falls on a weekend--moving to the following Monday"
        )
        deadlineDate += timedelta(days=8 - deadlineDate.isoweekday())

    installDeadlineString = deadlineDate.strftime("%Y-%m-%dT19:00:00")

    return installDeadlineString


## Check if there are any active DDM update plans for a given device
## If one is found, skip sending a new declaration, because it will fail
def checkExistingDevicePlans(deviceId, objectType="COMPUTER"):
    """
    Checks for existing active (non-failed) plans for a given device.

    Args:
        deviceId (str): The ID of the device to check for existing plans.
        objectType (str, optional): The type of the object. Defaults to "COMPUTER".

    Returns:
        dict or None: If no existing active plan is found, returns a dictionary with the deviceId and objectType.
                      If an existing active plan is found, returns None.

    Logs:
        Logs warnings if no deviceId is provided.
        Logs debug information about the attempts to check for existing plans and the results.
    """

    global existingPlanCount
    global existingPlans

    existingActivePlan = False

    if not deviceId:
        logging.warning(
            "No device ID found when attempting to check for existing plans!"
        )
        return None

    for i in range(1, 6):
        logging.debug(
            f"Checking for existing active (non-failed) plans for device {deviceId} (attempt {i} of 5)..."
        )
        existingActivePlan = False
        existingPlansResponse = jamfClient.pro_api_request(
            method="GET",
            resource_path=f"v1/managed-software-updates/plans?filter=device.deviceId=={deviceId}",
        )
        if existingPlansResponse.ok:
            planUUIDs = [
                x.get("planUuid") for x in existingPlansResponse.json().get("results")
            ]
            planRecords = map(getPlanData, planUUIDs)
            existingActivePlanData = next(
                (plan for plan in planRecords if not plan.get("planFailed")),
                None,
            )
            existingActivePlan = bool(existingActivePlanData)
            logging.debug(f"Existing active plan found: {existingActivePlan}")
            break

        else:
            logging.debug(
                f"Received {existingPlansResponse.status_code} checking for plan events, trying again..."
            )
            continue

    if not existingActivePlan:
        declarationItem = {"deviceId": deviceId, "objectType": objectType}
        return declarationItem
    else:
        existingPlanCount += 1
        existingActivePlan = {
            "planId": existingActivePlanData.get("planUuid"),
            "device": existingActivePlanData.get("device"),
        }
        existingPlans.append(existingActivePlan)
        return None


## Send DDM update plans to a device, a list of devices, or a group
def sendDeclaration(objectType, objectIds, installDeadlineString, osVersion):
    """
    Sends a declaration for macOS updates to specified devices or groups.

    Parameters:
    objectType (str): The type of object to target, either "computer" or "group".
    objectIds (int or list): The ID(s) of the target devices or group.
    installDeadlineString (str): The deadline for the installation in ISO 8601 format.
    osVersion (str): The version of macOS to update to.

    Returns:
    list or None: A list of plans if the declaration is successful, None otherwise.
    """

    global existingPlans

    if not re.match(r"^computer$|^group$", objectType, re.IGNORECASE):
        logging.error(
            f'Expected object type of "computer" or "group", received {objectType}'
        )
        return None

    objectType = objectType.upper()
    endpoint = "v1/managed-software-updates/plans"
    targetDeviceList = []

    if objectType == "GROUP":
        if not isinstance(objectIds, int):
            logging.error("Group ID must be specified as a single integer!")
            return None

        if groupData := fetchComputerGroupData(groupID=objectIds):
            groupMembers = groupData.computers
            eligibleDevices = jamfClient.concurrent_api_requests(
                checkDeviceDDMEligible, [device.id for device in groupMembers]
            )
            for device in eligibleDevices:
                if check_positive(device.id):
                    deviceConfig = {"deviceId": device.id, "objectType": "COMPUTER"}
                    targetDeviceList.append(deviceConfig)

        else:
            logging.error("Target group not found!")
            return None

    else:
        if (
            not isinstance(objectIds, (list, int))
            or isinstance(objectIds, str)
            and objectIds.isdigit()
        ):
            logging.error(
                "Target devices must be specified as a list or single integer!"
            )
            return None
        else:
            if not isinstance(objectIds, list) and check_positive(objectIds):
                objectIds = [objectIds]

            for device in objectIds:
                if check_positive(str(device)):
                    deviceConfig = {"deviceId": device, "objectType": "COMPUTER"}
                    targetDeviceList.append(deviceConfig)

    ## Check devices in target list for existing non-failed plans in progress
    eligibleTargetDevices = jamfClient.concurrent_api_requests(
        checkExistingDevicePlans,
        [device for device in targetDeviceList],
    )

    objectConfig = {"devices": [device for device in eligibleTargetDevices if device]}
    targetDeviceCount = len(objectConfig.get("devices"))

    if not targetDeviceCount:
        logging.error("No eligible devices targeted for this update, exiting!")
        return None

    logging.info(
        f"Sending DDM update for macOS {osVersion} to object type {objectType} ({str(targetDeviceCount) + " devices" if objectType != "GROUP" else "id: " + objectIds}) with a {installDeadlineString} deadline..."
    )

    delcarationConfig = {
        "config": {
            "updateAction": "DOWNLOAD_INSTALL_SCHEDULE",
            "versionType": "SPECIFIC_VERSION",
            "specificVersion": str(osVersion),
            "forceInstallLocalDateTime": installDeadlineString,
        }
    }

    delcarationConfig.update(objectConfig)

    ## Send the plans
    if not dryrun:
        logging.info("Sending declaration payload...")
        declarationResult = jamfClient.pro_api_request(
            "post", endpoint, data=delcarationConfig
        )

        if declarationResult.status_code == 201:
            logging.info("macOS update declaration was successfully sent")
            planList = declarationResult.json().get("plans")
            if existingPlans:
                planList.extend(existingPlans)

            return planList

        else:
            logging.error("Something went wrong creating the update declaration plan")
            return None

    else:
        logging.info(f"DRY RUN: DDM payload to be sent: {delcarationConfig}")

        return None


## Given a group ID or name, return data about the group
def fetchComputerGroupData(groupID=None, groupName=None):
    """
    Retrieve data for a computer group by its ID or name.

    This function queries the Jamf Classic API to get information about a computer group.
    The group can be identified either by its ID or its name.

    Args:
        groupID (int, optional): The ID of the computer group to retrieve.
        groupName (str, optional): The name of the computer group to retrieve.

    Returns:
        ClassicComputerGroup or None: An instance of ClassicComputerGroup if the group is found,
                                      otherwise None.

    Raises:
        Exception: If there is an issue with the API request.
    """

    if groupID:
        endpointType = "id"
        query = groupID

    elif groupName:
        endpointType = "name"
        query = groupName

    else:
        return None

    logging.info(f"Checking for computer group {endpointType} {query}...")
    try:
        groupDataRequest = jamfClient.classic_api_request(
            "get", f"computergroups/{endpointType}/{query}"
        )

        if groupDataRequest.ok:
            logging.debug("Found computer group")
            groupData = computer_groups.ClassicComputerGroup(
                **groupDataRequest.json()["computer_group"]
            )
            logging.debug(f"Group data: {groupData}")
            return groupData
    except requests.exceptions.RequestException as e:
        logging.warning(f"Computer group not found! Exception: {e}")
        return None


## Parse the provided SOFA feed for the latest macOS version data
def getVersionData():
    """
    Parses the latest SOFA feed for macOS updates and returns the update data.

    Depending on the target macOS version type, it retrieves the relevant version data
    from the feed and constructs a dictionary containing the update information.

    Returns:
        dict: A dictionary containing the following keys:
            - targetVersion: A dictionary with the following keys:
                - versionString (str): The product version string.
                - releaseDate (str): The release date of the update.
                - securityURL (str): The URL to the security information.
                - cveList (list): A list of CVE identifiers.
                - exploitedCVEs (list): A list of actively exploited CVEs.
                - supportedDevices (list): A list of supported devices.
            - latestPrior (optional): A dictionary with the same structure as targetVersion,
              representing the latest prior version data if the target version type is "MINOR".

    Logs:
        Logs information and debug messages about the parsing process and the constructed update data.
    """

    logging.info("Parsing the latest SOFA feed for macOS updates...")
    logging.info(f"Target macOS version is {targetVersionType}")

    if targetVersionType == "ANY" or targetVersionType == "MAJOR":
        versionData = feedData.get("OSVersions")[0].get("SecurityReleases")[0]

    elif targetVersionType == "MINOR":
        versionData = feedData.get("OSVersions")[0].get("SecurityReleases")[0]
        latestPriorVersionData = feedData.get("OSVersions")[1].get("SecurityReleases")[
            0
        ]

    else:
        majorVersion = str(Version(targetVersionType).major)
        majorVersionData = next(
            v
            for v in feedData.get("OSVersions")
            if v.get("OSVersion").split(" ")[1] == majorVersion
        )
        versionData = next(
            v
            for v in majorVersionData.get("SecurityReleases")
            if v.get("ProductVersion") == targetVersionType
        )

    updateData = {
        "targetVersion": {
            "versionString": versionData.get("ProductVersion"),
            "releaseDate": versionData.get("ReleaseDate"),
            "securityURL": versionData.get("SecurityInfo"),
            "cveList": list(versionData.get("CVEs").keys()),
            "supportedDevices": versionData.get("SupportedDevices"),
            "exploitedCVEs": list(versionData.get("ActivelyExploitedCVEs", [])),
        }
    }

    if "latestPriorVersionData" in locals():
        latestPriorData = {
            "latestPrior": {
                "versionString": latestPriorVersionData.get("ProductVersion"),
                "releaseDate": latestPriorVersionData.get("ReleaseDate"),
                "securityURL": latestPriorVersionData.get("SecurityInfo"),
                "cveList": list(latestPriorVersionData.get("CVEs").keys()),
                "exploitedCVEs": list(
                    latestPriorVersionData.get("ActivelyExploitedCVEs", [])
                ),
            }
        }

        updateData.update(latestPriorData)

    logging.debug(updateData)
    return updateData


## Determine the installation deadline (in days) based on runtime arguments and/or CVE data
def determineDeadline(cveList, exploitedCVEs):
    """
    Determines the installation deadline for a macOS update based on the provided CVE lists.

    Parameters:
    cveList (list): A list of CVEs addressed by the update.
    exploitedCVEs (list): A list of CVEs that are actively exploited.

    Returns:
    int: The number of days until the installation deadline.

    The function evaluates the risk associated with the CVEs in the update and sets an appropriate deadline:
    - If there are actively exploited CVEs, the deadline is accelerated.
    - If the update contains high-risk CVEs, the deadline is set to urgent.
    - If neither condition is met, a standard deadline is applied.
    - If a custom deadline is specified, it overrides the calculated deadline.
    """

    if len(cveList) > 0 and not customDeadline:
        highRiskUpdate = parseVulns(cveList)

        if len(exploitedCVEs) > 0:
            logging.info(
                f"Actively exploted CVEs found in this macOS update. Installation deadline will be accelerated. CVEs: {exploitedCVEs}"
            )
            deadlineDays = canaryDays

        elif highRiskUpdate:
            logging.info(
                "No known exploits in the wild for the CVEs patched in this release, but their aggregate risk scores warrant rapid remediation. Installation deadline will be accelerated."
            )
            deadlineDays = urgentDays

        else:
            logging.info(
                "No actively exploited CVEs listed for this release, proceeding with standard update deadline."
            )
            deadlineDays = standardDays
    elif customDeadline:
        logging.warning(
            "A custom deadline has been specified for this run. CVE checking will be skipped."
        )
        deadlineDays = standardDays

    logging.info(
        f"Calculated installation deadline for this update plan is {deadlineDays} days"
    )
    return deadlineDays


## Check to ensure the target version is available via DDM from jamf
def checkDeploymentAvailable(productVersion):
    """
    Check if a specific macOS version is available for deployment via Jamf.

    Args:
        productVersion (str): The macOS version to check for availability.

    Returns:
        bool: True if the specified macOS version is available for deployment, False otherwise.

    Logs:
        - An error message if the specified macOS version is not available.
        - An error message if the Jamf API request fails.
        - An info message if the specified macOS version is available for deployment.
    """

    availableUpdateData = jamfClient.pro_api_request(
        "get", "v1/managed-software-updates/available-updates"
    )

    if availableUpdateData.ok:
        availableUpdates = availableUpdateData.json().get("availableUpdates")
        if availableUpdates is None:
            logging.error("No available updates found in the response.")
            return False

        macOSVersions = availableUpdates.get("macOS")

        if productVersion not in macOSVersions:
            logging.error(
                f"{productVersion} does not yet seem to be available in jamf as a managed update target. Try again later."
            )
            return False

    else:
        logging.error(
            f"Got {availableUpdateData.status_code} back from jamf API: {availableUpdateData.content}"
        )
        return False

    logging.info(f"jamf reports {productVersion} is available for DDM deployment")
    return True


## Before attempting to send a declaration, verify a given device is eligible to receive and process it
## Required criteria:
## - Device is DDM enabled
## - Device has a bootstrap token escrowed in jamf
## - Device is running macOS Sonoma or newer
def checkDeviceDDMEligible(deviceRecord):
    """
    Checks if a device is eligible for Declarative Device Management (DDM) updates.

    Args:
        deviceRecord (computers.Computer, int, str): The device record to check. It can be an instance of
        `computers.Computer`, an integer representing the device ID, or a string representing the device ID.

    Returns:
        computers.Computer or None: Returns the device object if it is eligible for DDM updates, otherwise returns None.

    Logs:
        Logs an error if the device record is missing or malformed.
        Logs debug information about the device's DDM eligibility.
        Logs a warning if the device does not meet the criteria for DDM updates.

    Eligibility Criteria:
        - The device must have DDM enabled.
        - The device must have an escrowed bootstrap token.
        - The device's operating system version must be at least macOS Sonoma (version 14).
    """
    if not isinstance(deviceRecord, (computers.Computer, int, str)):
        logging.error(
            "Computer record missing or malformed, cannot check DDM eligibility!"
        )
        return None

    if (
        isinstance(deviceRecord, int)
        or isinstance(deviceRecord, str)
        and str(deviceRecord).isdigit()
    ):
        device = computers.Computer(
            **jamfClient.pro_api_request(
                method="GET",
                resource_path=f"v1/computers-inventory-detail/{deviceRecord}",
            ).json()
        )
    else:
        device = deviceRecord

    if (
        isinstance(device, computers.Computer)
        and device.operatingSystem.version is not None
    ):
        logging.debug(f"Checking DDM update eligibility for device {device.id}...")
    else:
        logging.error(
            "Unable to retrieve device inventory, cannot check DDM eligibility!"
        )
        return None

    deviceIsDDMEnabled = device.general.declarativeDeviceManagementEnabled
    deviceHasBootstrapToken = device.security.bootstrapTokenEscrowedStatus == "ESCROWED"
    deviceOSVersionIsAtLeastSonoma = Version(device.operatingSystem.version).major >= 14

    deviceEligibilityData = {
        "deviceIsDDMEnabled": deviceIsDDMEnabled,
        "deviceHasBootstrapToken": deviceHasBootstrapToken,
        "deviceOSVersionIsAtLeastSonoma": deviceOSVersionIsAtLeastSonoma,
    }

    if all(v for k, v in deviceEligibilityData.items()):
        logging.debug("DDM updates can be deployed to this device")
        return device
    else:
        logging.warning(
            f"Some criteria were not met when checking DDM update eligibility for device ID {device.id}. "
            f"Update plans will not be sent to this device.\n\nEligibility failed the following check(s):\n"
            f"{', '.join([k for k in deviceEligibilityData if not deviceEligibilityData.get(k)])}\n"
        )
        return None


## Given an update plan UUID, retrieve and return data about the plan and its status/history
def getPlanData(planUUID):
    """
    Fetches and returns detailed plan data for a given plan UUID from the Jamf Pro API.

    Args:
        planUUID (str): The UUID of the plan to fetch data for.

    Returns:
        dict: A dictionary containing the plan data, including:
            - planUuid (str): The UUID of the plan.
            - planCreated (int): The epoch time when the plan was created.
            - deviceData (dict): Information about the device associated with the plan.
            - installDeadline (str): The installation deadline as a string, if available.
            - deadlineExceeded (bool): Whether the installation deadline has been exceeded.
            - targetVersionString (str): The target OS version specified in the plan configuration.
            - planCompleted (bool): Whether the device has been updated to the target OS version.
            - planFailed (bool): Whether the plan has failed based on errors, deadline, or target version.
            - planErrors (list): A list of error reasons associated with the plan.

    Returns None if the planUUID is not specified or if there is an error fetching the plan data.

    Raises:
        Exception: If there are issues with the Jamf Pro API requests or data processing.
    """
    if not planUUID:
        logging.error("No plan UUID specified, cannot get plan data")
        return None
    logging.debug(f"Fetching plan data for {planUUID}...")

    planDeclarations = {}
    planEvents = {}
    ## If a plan was just created, it can take jamf some time to fully report
    for i in range(1, 6):
        logging.debug(
            f"Fetching declarations and events for plan {planUUID} (attempt {i} of 5)..."
        )
        planEventsResponse = jamfClient.pro_api_request(
            method="GET",
            resource_path=f"v1/managed-software-updates/plans/{planUUID}/events",
        )

        if not planEventsResponse.ok:
            logging.debug(
                f"Received {planEventsResponse.status_code} checking for plan events, trying again..."
            )
            continue

        if not planEventsResponse.json().get("events"):
            logging.debug(f"Events not ready yet, backing off and trying again...")
            time.sleep(5)
        else:
            planDeclarationsResponse = jamfClient.pro_api_request(
                method="GET",
                resource_path=f"v1/managed-software-updates/plans/{planUUID}/declarations",
            )

            if not planDeclarationsResponse.ok:
                logging.debug(
                    f"Received {planDeclarationsResponse.status_code} checking for plan declarations, trying again..."
                )
                continue

            planDeclarations = planDeclarationsResponse.json()
            logging.debug(f"Plan Declarations: {planDeclarations}")
            planEvents = json.loads(planEventsResponse.json().get("events")).get(
                "events"
            )
            logging.debug(f"Plan Events: {planEvents}")
            planCreatedJamf = next(
                i.get("eventReceivedEpoch")
                for i in planEvents
                if i.get("type") == ".PlanCreatedEvent"
            )
            planCreatedTimestamp = convertJamfTimestamp(planCreatedJamf)
            if planCreatedTimestamp:
                planCreatedEpoch = planCreatedTimestamp.get("epochTime")
            else:
                logging.error("Failed to convert Jamf timestamp, exiting!")
                return None
            break

    ## Full plan info might not be available until after declarations and events have been recorded
    ## Need to allow a bit of time for jamf to catch up
    currentEpochTime = int(datetime.now(timezone.utc).strftime("%s"))
    planCreatedDelta = currentEpochTime - int(planCreatedEpoch)

    if planCreatedDelta <= 30:
        logging.debug(
            f"This plan was created {planCreatedDelta} seconds ago--allowing some extra time for jamf to catch up before fetching additional plan data..."
        )
        time.sleep(5)

    planInfoResponse = jamfClient.pro_api_request(
        method="GET", resource_path=f"v1/managed-software-updates/plans/{planUUID}"
    )

    if planInfoResponse.ok:
        logging.debug("Successfully retrieved plan data")
        planInfo = planInfoResponse.json()
        logging.debug(f"Plan Information: {planInfo}")
        planErrors = planInfo.get("status").get("errorReasons")
        logging.debug(f"Plan Errors: {planErrors}")

        declarationConfiguration = next(
            (
                i.get("payloadJson")
                for i in planDeclarations.get("declarations")
                if i.get("group") == "CONFIGURATION"
            ),
            None,
        )

        installDeadlineString = planInfo.get("forceInstallLocalDateTime", None)
        if installDeadlineString:
            installDeadline = datetime.strptime(
                installDeadlineString, "%Y-%m-%dT%H:%M:%S"
            )
            currentDateTime = datetime.now()
            deadlineDelta = installDeadline - currentDateTime
            deadlineExceeded = True if deadlineDelta.total_seconds() < 0 else False
        else:
            deadlineExceeded = None
        deviceData = planInfo.get("device")
        if deviceCurrentOSVersion := next(
            (
                device.operatingSystem.version
                for device in outdatedDevices
                if device.id == deviceData.get("deviceId")
            ),
            None,
        ):
            logging.debug(
                f"Retrieved device current OS version: {deviceCurrentOSVersion}"
            )
        else:
            deviceCurrentOSData = jamfClient.pro_api_request(
                method="GET",
                resource_path=deviceData.get("href").lstrip("/"),
                query_params={"section": "OPERATING_SYSTEM"},
            )
            if deviceCurrentOSData.ok:
                deviceCurrentOSVersion = computers.Computer(
                    **deviceCurrentOSData.json()
                ).operatingSystem.version
                logging.debug(
                    f"Retrieved device current OS version: {deviceCurrentOSVersion}"
                )
            else:
                logging.error(
                    f"Failed to retrieve device current OS version for device {deviceData.get("deviceId")}"
                )
                deviceCurrentOSVersion = "0"
            logging.debug(
                f"Retrieved device current OS version: {deviceCurrentOSVersion}"
            )
        if declarationConfiguration:
            configurationJson = json.loads(declarationConfiguration)
            targetVersionString = configurationJson.get("TargetOSVersion")
            deviceUpdated = bool(
                Version(deviceCurrentOSVersion) >= Version(targetVersionString)
            )
        else:
            targetVersionString = None
            deviceUpdated = False
        planData = {
            "planUuid": planUUID,
            "planCreated": planCreatedEpoch,
            "deviceData": planInfo.get("device"),
            "installDeadline": installDeadlineString,
            "deadlineExceeded": deadlineExceeded,
            "targetVersionString": targetVersionString,
            "planCompleted": deviceUpdated,
            "planFailed": (
                True
                if any([len(planErrors) > 0, deadlineExceeded, not targetVersionString])
                else False
            ),
            "planErrors": planErrors,
        }
        logging.debug(f"Retrieved plan data: {planData}")
        return planData
    else:
        logging.error("Error encountered fetching plan data")
        return None


## Given a list of update plans, there may be multiple plan records for a single device
## Filter the list to include only the most recently created plan per device
def deduplicatePlans(planList):
    """
    Deduplicate a list of plans by selecting the latest plan for each unique device ID.

    Args:
        planList (list): A list of dictionaries, where each dictionary represents a plan.
                         Each dictionary must contain a 'deviceData' key with a nested 'deviceId' key,
                         and a 'planCreated' key indicating the creation time of the plan.

    Returns:
        list: A list of dictionaries containing the latest plan for each unique device ID.
              Returns None if the input is not a list.

    Logs:
        Logs information about the deduplication process, including errors if the input is not a list,
        and debug information about the plans being processed and selected.
    """
    logging.info("Finding the latest plan for each device ID in the provided list...")
    if not isinstance(planList, list):
        logging.error(f"Expected a list, received {type(planList)}")
        return None
    filteredPlanList = []
    planDevices = set(
        i["deviceData"]["deviceId"]
        for i in planList
        if isinstance(i, dict) and "deviceData" in i and "deviceId" in i["deviceData"]
    )
    for device in planDevices:
        logging.debug(f"Checking list for plans associated with device ID {device}")
        latestPlanEpoch = sorted(
            (
                i.get("planCreated")
                for i in planList
                if i.get("deviceData").get("deviceId") == device
            ),
            reverse=True,
        )[0]
        devicePlans = [
            i for i in planList if i.get("deviceData").get("deviceId") == device
        ]
        latestPlanData = next(
            i for i in devicePlans if i.get("planCreated") == latestPlanEpoch
        )

        if latestPlanData:
            logging.debug(
                f"Found plan for device {device} started at {latestPlanEpoch}..."
            )
            filteredPlanList.append(latestPlanData)
    return filteredPlanList


## Retry a failed plan
def retryPlan(plan):
    """
    Retries the update plan for a given device.

    Parameters:
    plan (dict): A dictionary containing the update plan data. Expected keys include:
        - deviceData (dict): A dictionary containing device information.
            - deviceId (str): The ID of the device.
        - installDeadline (str): The current installation deadline.
        - deadlineExceeded (bool): A flag indicating if the deadline has been exceeded.
        - targetVersionString (str): The target OS version for the update.
        - planErrors (list): A list of errors associated with the plan.

    Returns:
    dict or None: A dictionary containing the new plan data if successful, or None if the plan could not be retried.
    """

    if not plan:
        logging.error("No plan data received to retry!")
        return None

    deviceId = plan.get("deviceId")
    currentDeadline = plan.get("installDeadline")
    deadlineExceeded = plan.get("deadlineExceeded")
    targetVersionString = plan.get("targetVersionString")
    planErrors = plan.get("planErrors")

    logging.info(f"Retrying update declaration for device {deviceId}...")

    if deadlineExceeded:
        logging.debug(
            "Existing deadline for this plan has elapsed. Resetting for 3 days out."
        )
        newDeadline = calculateDeadlineString(3)
    else:
        logging.debug(f"Existing deadline of {currentDeadline} is still valid")
        newDeadline = currentDeadline

    newPlan = sendDeclaration(
        objectType="computer",
        objectIds=deviceId,
        installDeadlineString=newDeadline,
        osVersion=targetVersionString,
    )

    if newPlan:
        newPlanId = newPlan[0].get("planId")
        newPlanData = getPlanData(newPlanId)
    else:
        logging.error(f"Failed to create a new plan for device {deviceId}")
        return None
    logging.info(f"Successfully created a new plan for device {deviceId}: {newPlanId}")
    return newPlanData


## Do the things
def run():
    """
    Executes the macOS update processor script.

    This function performs the following tasks:
    1. Validates run conditions and configures the Jamf API client.
    2. Checks if DDM updates are enabled on the Jamf tenant.
    3. Loads existing plan data if available.
    4. Validates the timestamp and feed data hashes.
    5. Parses the latest SOFA feed for macOS updates.
    6. Determines the target version and its associated data.
    7. Generates a run summary with configured options.
    8. Checks and retries existing plans if specified.
    9. Retrieves the list of devices not running the target macOS version.
    10. Filters devices based on group memberships and eligibility.
    11. Splits target devices between N and N-1 major versions if applicable.
    12. Sends update plans to the Jamf API.
    13. Logs the run results and updates the metadata file.

    Global Variables:
    - outdatedDevices: List of devices that are outdated.
    - canaryGroupName: Name of the canary group.
    - existingPlanCount: Count of existing plans.
    - existingPlans: List of existing plans.
    - targetVersionSupportedDevices: List of devices supported by the target version.

    Raises:
    - Ends the run with an appropriate message and status code if any critical condition fails.
    """

    ## Declare global args
    global outdatedDevices
    global canaryGroupName
    global existingPlanCount
    global existingPlans
    global targetVersionSupportedDevices

    logging.debug("Validating run conditions...")

    ## Configure the jamf API client
    if not all([jamfURL, jamfClientID, jamfClientSecret]):
        endRun(1, "critical", "Jamf Pro URL and/or credentials not found!")

    else:
        global jamfClient

        jamfClient = JamfProClient(
            server=jamfURL,
            credentials=ApiClientCredentialsProvider(jamfClientID, jamfClientSecret),
            session_config=SessionConfig(
                **{"timeout": 30, "max_retries": 5, "max_concurrency": 25}
            ),
        )

    ## Make sure DDM updates are enabled on the jamf tenant
    logging.debug("Checking to ensure DDM updates are enabled...")
    toggleCheckResponse = jamfClient.pro_api_request(
        method="GET", resource_path="v1/managed-software-updates/plans/feature-toggle"
    ).json()
    if toggleCheckResponse.get("toggle", None) == True:
        logging.debug("DDM updates are enabled")
    else:
        endRun(
            1,
            logLevel="critical",
            message="DDM updates do not appear to be enabled on this jamf tenant. Please check your settings and try again.",
        )

    if dataFilePath.exists():
        logging.info(f"Found metadata file at {dataFilePath}, processing...")
        currentPlanData = loadJson(dataFilePath)

    else:
        currentPlanData = None

    lastRunTime = timestampData.get("macOS").get("LastCheck").replace("Z", "")
    currentEpochTime = int(datetime.now(timezone.utc).strftime("%s"))
    lastRunTimeEpoch = int(datetime.fromisoformat(lastRunTime).strftime("%s"))
    runDelta = currentEpochTime - lastRunTimeEpoch

    if runDelta >= 604800:
        logging.warning(
            f"The current run data is over a week old. Ensure the data feed builder is running properly."
        )

    timestampHash = timestampData.get("macOS").get("UpdateHash")
    dataHash = feedData.get("UpdateHash")

    ## Fail out if the hashes don't match
    if timestampHash != dataHash:
        endRun(
            1,
            logLevel="critical",
            message=f"Feed data hash {dataHash} does not match hash found in timestamp data ({timestampHash})! Verify your SOFA feed.",
        )

    logging.info("Parsing the latest SOFA feed for macOS updates...")

    outdatedDevices = []
    updateData = getVersionData()
    createdPlans = []
    existingPlans = []
    isCanary = False

    targetVersionData = updateData.get("targetVersion")
    targetVersionString = targetVersionData.get("versionString")
    releaseDate = targetVersionData.get("releaseDate")
    cveList = targetVersionData.get("cveList")
    exploitedCVEs = targetVersionData.get("exploitedCVEs")
    targetVersionSupportedDevices = targetVersionData.get("supportedDevices")

    if targetVersionType == "MINOR":
        logging.info(
            f"Initializing update plans for the latest minor macOS version. N and N-1 major releases will be targeted."
        )
        latestPriorData = updateData.get("latestPrior")
        latestPriorVersionString = latestPriorData.get("versionString")
        latestPriorReleaseDate = latestPriorData.get("releaseDate")
        latestPriorCVEList = latestPriorData.get("cveList")
        latestPriorExploitedCVEs = latestPriorData.get("exploitedCVEs")

        latestPriorDeadlineDays = determineDeadline(
            latestPriorCVEList, latestPriorExploitedCVEs
        )

        logging.info(f"Latest N-1 release is {latestPriorVersionString}")
        logging.info(
            f"Installation of this update for targeted devices will be required in {latestPriorDeadlineDays} days"
        )

    else:
        logging.info(
            f"Initializing update plans for macOS version {targetVersionString}"
        )

    deadlineDays = determineDeadline(cveList, exploitedCVEs)
    logging.info(
        f"Installation of this update for targeted devices will be required in {deadlineDays} days"
    )

    if forceDays:
        logging.info(f"Forced update detected--setting deadline of {forceDays} days")
        deadlineDays = forceDays
        canaryGroupName = None

    ## Begin generating run summary
    createdPlanCount = 0
    failedPlanCount = 0
    existingPlanCount = 0
    runSummary = f"""
#######################################
#### DDM Update Deployment Summary ####
#######################################

## Run Started: {datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")}

## Configured Options:
- jamf URL: {jamfURL}
- Target Version Type: {targetVersionType}
- Latest macOS Version: {targetVersionString}
"""

    if targetVersionType == "MINOR":
        runSummary = (
            runSummary + f"- Latest N-1 macOS Version: {latestPriorVersionString}\n"
        )

    if excludedGroupName:
        runSummary = runSummary + f"- Excluded Group: {excludedGroupName}\n"

    if overrideGroupName:
        runSummary = runSummary + f"- Override Group: {overrideGroupName}\n"

    if canaryGroupName:
        runSummary = (
            runSummary
            + f"""
- Canary Group: {canaryGroupName}
- Canary Deployment OK: {canaryOK}
- Canary Version Deployed: {canaryVersion}

"""
        )

    runSummary = runSummary + f"- Dry Run: {dryrun}\n\n"

    if checkPlans or retryPlans:
        runSummary = (
            runSummary
            + f"""
- Check Existing Plans: {checkPlans}
- Retry Failed Plans: {retryPlans}

"""
        )
        checkedPlanCount = 0
        retriedPlanCount = 0
        ## load current plans and check them. if retry, recalc deadline if needed and re-send failures
        if not currentPlanData:
            endRun(
                1,
                logLevel="error",
                message="Check or retry options were specified but no existing plan data was found. Please verify your data file path and try again.",
            )

        latestCanaryPlans, latestStandardPlans, priorCanaryPlans, priorStandardPlans = (
            [],
            [],
            [],
            [],
        )

        if currentPlans := currentPlanData.get("latest"):
            if latestCanaryPlanData := currentPlans.get("canary"):
                latestCanaryPlans = deduplicatePlans(latestCanaryPlanData.get("plans"))
                checkedPlanCount += len(latestCanaryPlans)
                planCheckResults = jamfClient.concurrent_api_requests(
                    getPlanData, [p.get("planUuid") for p in latestCanaryPlans]
                )
                for plan in planCheckResults:
                    ## fix these pops in check/retry logic
                    ## maybe not required
                    latestCanaryPlans.pop(
                        latestCanaryPlans.index(
                            next(
                                i
                                for i in latestCanaryPlans
                                if i.get("planUuid") == plan.get("planUuid")
                            )
                        )
                    )

                    if plan.get("planFailed") and retryPlans:
                        plan = retryPlan(plan)
                        retriedPlanCount += 1

                    latestCanaryPlans.append(plan)

                currentPlanData.update(
                    {"latest": {"canary": {"plans": latestCanaryPlans}}}
                )

            if latestStandardPlanData := currentPlans.get("standard"):
                latestStandardPlans = deduplicatePlans(
                    latestStandardPlanData.get("plans")
                )
                checkedPlanCount += len(latestStandardPlans)
                planCheckResults = jamfClient.concurrent_api_requests(
                    getPlanData, [p.get("planUuid") for p in latestStandardPlans]
                )
                for plan in planCheckResults:
                    latestStandardPlans.pop(
                        latestStandardPlans.index(
                            next(
                                i
                                for i in latestStandardPlans
                                if i.get("planUuid") == plan.get("planUuid")
                            )
                        )
                    )
                    latestStandardPlans.append(plan)

                    if plan.get("planFailed") and retryPlans:
                        plan = retryPlan(plan)
                        retriedPlanCount += 1

                    latestStandardPlans.append(plan)

                currentPlanData.update(
                    {"latest": {"standard": {"plans": latestStandardPlans}}}
                )

        if priorMajorPlans := currentPlanData.get("latestPrior"):
            if priorCanaryPlanData := priorMajorPlans.get("canary"):
                priorCanaryPlans = deduplicatePlans(priorCanaryPlanData.get("plans"))
                checkedPlanCount += len(priorCanaryPlans)
                planCheckResults = jamfClient.concurrent_api_requests(
                    getPlanData, [p.get("planUuid") for p in priorCanaryPlans]
                )
                for plan in planCheckResults:
                    priorCanaryPlans.pop(
                        priorCanaryPlans.index(
                            next(
                                i
                                for i in priorCanaryPlans
                                if i.get("planUuid") == plan.get("planUuid")
                            )
                        )
                    )
                    priorCanaryPlans.append(plan)

                    if plan.get("planFailed") and retryPlans:
                        plan = retryPlan(plan)
                        retriedPlanCount += 1

                    priorCanaryPlans.append(plan)

                currentPlanData.update(
                    {"latestPrior": {"canary": {"plans": priorCanaryPlans}}}
                )

            if priorStandardPlanData := priorMajorPlans.get("standard"):
                priorStandardPlans = deduplicatePlans(
                    priorStandardPlanData.get("plans")
                )
                checkedPlanCount += len(priorStandardPlans)
                planCheckResults = jamfClient.concurrent_api_requests(
                    getPlanData, [p.get("planUuid") for p in priorStandardPlans]
                )
                for plan in planCheckResults:
                    priorStandardPlans.pop(
                        priorStandardPlans.index(
                            next(
                                i
                                for i in priorStandardPlans
                                if i.get("planUuid") == plan.get("planUuid")
                            )
                        )
                    )
                    priorStandardPlans.append(plan)

                    if plan.get("planFailed") and retryPlans:
                        plan = retryPlan(plan)
                        retriedPlanCount += 1

                    priorStandardPlans.append(plan)

                currentPlanData.update(
                    {"latestPrior": {"standard": {"plans": priorStandardPlans}}}
                )

        if not any(
            [
                latestCanaryPlans,
                latestStandardPlans,
                priorCanaryPlans,
                priorStandardPlans,
            ]
        ):
            endRun(0, message="No existing plans found to check, exiting...")

        dumpJson(currentPlanData, dataFilePath)
        runSummary = (
            runSummary
            + f"""
- Checked Plans: {checkedPlanCount}
- Retried Plans: {retriedPlanCount}

## Run Finished: {datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")}
"""
        )
        logging.info("Plan checks completed and metadata updated, exiting.")
        endRun(0, message=runSummary)

    logging.info(
        f"Retrieving list of devices not running at least macOS {targetVersionString}..."
    )
    if targetVersionType == "MINOR":
        outdatedDevicesFilter = filter_group(
            FilterField("general.remoteManagement.managed").eq(True)
        ) & filter_group(
            filter_group(
                FilterField("operatingSystem.version").eq(
                    str(Version(targetVersionString).major) + ".*"
                )
                & FilterField("operatingSystem.version").lt(targetVersionString)
            )
            | filter_group(
                FilterField("operatingSystem.version").eq(
                    str(Version(latestPriorVersionString).major) + ".*"
                )
                & FilterField("operatingSystem.version").lt(latestPriorVersionString)
            )
        )
    elif targetVersionType == "MAJOR":
        outdatedDevicesFilter = filter_group(
            FilterField("general.remoteManagement.managed").eq(True)
        ) & filter_group(
            FilterField("operatingSystem.version").eq(
                str(Version(targetVersionString).major) + ".*"
            )
            & FilterField("operatingSystem.version").lt(targetVersionString)
        )
    else:
        outdatedDevicesFilter = FilterField("general.remoteManagement.managed").eq(
            True
        ) & FilterField("operatingSystem.version").lt(targetVersionString)

    outdatedDevices = jamfClient.pro_api.get_computer_inventory_v1(
        sections=[
            "GENERAL",
            "HARDWARE",
            "OPERATING_SYSTEM",
            "SECURITY",
            "GROUP_MEMBERSHIPS",
        ],
        filter_expression=outdatedDevicesFilter,
        return_generator=False,
    )

    ## if any group operations are being done, filter results accordingly
    if groupData := fetchComputerGroupData(groupName=excludedGroupName):
        logging.info(f"Excluding devices in group {excludedGroupName}")
        groupMembers = [str(member.id) for member in groupData.computers]
        popIndices = []
        for device in outdatedDevices:
            if str(device.id) in groupMembers:
                if deviceIndex := next(
                    (
                        index
                        for (index, d) in enumerate(outdatedDevices)
                        if d.id == device.id
                    ),
                    None,
                ):
                    logging.debug(
                        f"Removing device {device.id} from list at index {deviceIndex}..."
                    )
                    popIndices.append(deviceIndex)
        for i in sorted(popIndices, reverse=True):
            outdatedDevices.pop(i)
        logging.info(f"Filtered to {len(outdatedDevices)} outdated devices")

    if groupData := fetchComputerGroupData(groupName=overrideGroupName):
        logging.info(f"Filtering to only devices in group {overrideGroupName}")
        groupMembers = [str(member.id) for member in groupData.computers]
        popIndices = []
        for device in outdatedDevices:
            if str(device.id) not in groupMembers:
                if deviceIndex := next(
                    (
                        index
                        for (index, d) in enumerate(outdatedDevices)
                        if d.id == device.id
                    ),
                    None,
                ):
                    logging.debug(
                        f"Removing device {device.id} from list at index {deviceIndex}..."
                    )
                    popIndices.append(deviceIndex)
        for i in sorted(popIndices, reverse=True):
            outdatedDevices.pop(i)
        logging.info(f"Filtered to {len(outdatedDevices)} outdated devices")
        isCanary = False

    ## deal with canary group filtering
    if groupData := fetchComputerGroupData(groupName=canaryGroupName):

        if targetVersionType == "MINOR":
            logging.error(
                'Canary deployments are currently not compatible with the "MINOR" target version type.'
            )
            endRun(1)

        if not canaryOK:

            logging.info(f"Filtering to only devices in canary group {canaryGroupName}")

            for device in outdatedDevices:
                groupMembers = [str(member.id) for member in groupData.computers]
                popIndices = []
                for device in outdatedDevices:
                    if str(device.id) not in groupMembers:
                        if deviceIndex := next(
                            (
                                index
                                for (index, d) in enumerate(outdatedDevices)
                                if d.id == device.id
                            ),
                            None,
                        ):
                            logging.debug(
                                f"Removing device {device.id} from list at index {deviceIndex}..."
                            )
                            popIndices.append(deviceIndex)
                for i in sorted(popIndices, reverse=True):
                    outdatedDevices.pop(i)
            logging.info(f"Filtered to {len(outdatedDevices)} outdated devices")
            deadlineDays = canaryDays
            isCanary = True

        else:

            if canaryVersion == targetVersionString:

                logging.info(
                    f"Canary version {canaryVersion} matches current, proceeding with wide deployment"
                )
                for device in outdatedDevices:
                    groupMembers = [str(member.id) for member in groupData.computers]
                    popIndices = []
                    for device in outdatedDevices:
                        if str(device.id) in groupMembers:
                            if deviceIndex := next(
                                (
                                    index
                                    for (index, d) in enumerate(outdatedDevices)
                                    if d.id == device.id
                                ),
                                None,
                            ):
                                logging.debug(
                                    f"Removing device {device.id} from list at index {deviceIndex}..."
                                )
                                popIndices.append(deviceIndex)
                    for i in sorted(popIndices, reverse=True):
                        outdatedDevices.pop(i)
                logging.info(f"Filtered to {len(outdatedDevices)} outdated devices")
                isCanary = False

            else:

                logging.warning(
                    f"Canary version {canaryVersion} does not match current release {targetVersionString}! Ending run out of an abundance of caution. Please verify your canary deployment and try again."
                )
                endRun(1)

    ## filter out ineligible devices
    logging.info("Verifying update deployment eligibility for in-scope devices...")
    ineligibleDevices = []
    popIndices = []
    for device in outdatedDevices:
        if not all([checkDeviceDDMEligible(device), checkModelSupported(device)]):
            ineligibleDevices.append(device.id)
            if deviceIndex := next(
                (
                    index
                    for (index, d) in enumerate(outdatedDevices)
                    if d.id == device.id
                ),
                None,
            ):
                logging.debug(
                    f"Removing device {device.id} from list at index {deviceIndex}..."
                )
                popIndices.append(deviceIndex)

    if len(ineligibleDevices) > 0:
        logging.warning(
            f"Found {len(ineligibleDevices)} devices ineligible for DDM update deployment. See run summary for details.\nDeployment will proceed to remaining eligible devices.\n"
        )
        for i in sorted(popIndices, reverse=True):
            outdatedDevices.pop(i)
    else:
        logging.info("All in-scope devices eligible for DDM update deployment!")

    ## if MINOR deployment, split out results between N major version and N-1
    if targetVersionType == "MINOR":
        currentMajorVersion = Version(targetVersionString).major
        priorMajorVersion = Version(latestPriorVersionString).major
        logging.info(
            f"Splitting target device list to N ({currentMajorVersion}) and N-1 ({priorMajorVersion}) major versions..."
        )

        currentMajorTargets = []
        priorMajorTargets = []

        for device in outdatedDevices:
            if Version(device.operatingSystem.version).major == currentMajorVersion:
                logging.debug(
                    f"Adding device {device.id} to current major version targets..."
                )
                currentMajorTargets.append(device)

            elif Version(device.operatingSystem.version).major == priorMajorVersion:
                if Version(device.operatingSystem.version) < Version(
                    latestPriorVersionString
                ):
                    logging.debug(
                        f"Adding device {device.id} to prior major version targets..."
                    )
                    priorMajorTargets.append(device)
                else:
                    logging.debug(
                        f"Device {device.id} appears to already be up to date with the latest version of N-1."
                    )

            else:
                logging.warning(
                    f"Unable to determine major version target for device {device.id}! Adding to prior major version targets..."
                )
                priorMajorTargets.append(device)

        logging.info(
            f"Found {len(currentMajorTargets)} eligible devices requiring an update for macOS {currentMajorVersion}"
        )
        logging.info(
            f"Found {len(priorMajorTargets)} eligible devices requiring an update for macOS {priorMajorVersion}"
        )

    else:
        currentMajorTargets = [
            device
            for device in outdatedDevices
            if Version(device.operatingSystem.version) < Version(targetVersionString)
        ]
        logging.info(f"Found {len(currentMajorTargets)} outdated devices")
        logging.info(
            f"Sending the latest and greatest from Cuptertino to all in-scope devices..."
        )

    ## send plans
    planData = dict()
    if targetVersionType == "MINOR" and len(priorMajorTargets) > 0:
        installDeadlineString = calculateDeadlineString(latestPriorDeadlineDays)
        if planSuccessData := sendDeclaration(
            objectType="computer",
            objectIds=[computer.id for computer in priorMajorTargets],
            installDeadlineString=installDeadlineString,
            osVersion=latestPriorVersionString,
        ):

            for plan in jamfClient.concurrent_api_requests(
                getPlanData, [p.get("planId") for p in planSuccessData]
            ):
                createdPlans.append(plan)
                createdPlanCount += 1
                if plan.get("planFailed"):
                    failedPlanCount += 1

            priorPlanData = {
                "prior": {
                    "canary" if isCanary else "standard": {
                        "planCreated": datetime.strftime(
                            datetime.now(), "%Y-%m-%dT%H:%M:%S"
                        ),
                        "targetVersion": latestPriorVersionString,
                        "installationDeadline": installDeadlineString,
                        "installationDeadlineEpoch": int(
                            datetime.timestamp(
                                datetime.strptime(
                                    installDeadlineString, "%Y-%m-%dT%H:%M:%S"
                                )
                            )
                        ),
                        "plans": createdPlans,
                    }
                }
            }

            planData.update(priorPlanData)

        elif not dryrun:
            logging.error("Something went wrong sending this plan")

    installDeadlineString = calculateDeadlineString(deadlineDays)
    if planSuccessData := sendDeclaration(
        objectType="computer",
        objectIds=[computer.id for computer in currentMajorTargets],
        installDeadlineString=installDeadlineString,
        osVersion=targetVersionString,
    ):

        for plan in jamfClient.concurrent_api_requests(
            getPlanData, [p.get("planId") for p in planSuccessData]
        ):
            createdPlans.append(plan)
            createdPlanCount += 1
            if plan.get("planFailed"):
                failedPlanCount += 1

        latestPlanData = {
            "latest": {
                "canary" if isCanary else "standard": {
                    "planCreated": datetime.strftime(
                        datetime.now(), "%Y-%m-%dT%H:%M:%S"
                    ),
                    "targetVersion": targetVersionString,
                    "installationDeadline": installDeadlineString,
                    "installationDeadlineEpoch": int(
                        datetime.timestamp(
                            datetime.strptime(
                                installDeadlineString, "%Y-%m-%dT%H:%M:%S"
                            )
                        )
                    ),
                    "plans": createdPlans,
                }
            }
        }

        planData.update(latestPlanData)

    elif not dryrun:
        logging.error("Something went wrong sending this plan")

    runSummary = (
        runSummary
        + f"""
## Run Results:
- Total outdated devices in scope: {len(outdatedDevices)}
- Devices ineligible for update deployment: {len(ineligibleDevices)}
{"- Ineligible device IDs: " + ", ".join(ineligibleDevices) if ineligibleDevices else ""}
- Devices with Existing Active Plans: {existingPlanCount}
- Update plans created: {createdPlanCount - existingPlanCount if not dryrun else "0 (dry run)"}
- Update plans failed: {failedPlanCount if not dryrun else "0 (dry run)"}

## Run Finished: {datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")}

## Full log available at {logFile}
    """
    )

    if not dryrun and planData:
        dumpJson(planData, dataFilePath)

    else:
        logging.debug(planData)

    endRun(0, message=runSummary)


if __name__ == "__main__":
    run()
