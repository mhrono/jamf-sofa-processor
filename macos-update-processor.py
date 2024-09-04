#!/usr/bin/env python3

import argparse
import json
import logging
import os
import re
import time
import sys
import requests
from pathlib import Path
from datetime import datetime, timedelta, timezone
from tempfile import NamedTemporaryFile

from jamf_pro_sdk import JamfProClient, SessionConfig
from jamf_pro_sdk.models.classic import computer_groups
from jamf_pro_sdk.clients.auth import ApiClientCredentialsProvider
from jamf_pro_sdk.helpers import logger_quick_setup

## Version
scriptVersion = "0.1"

## Arguments


## Validate integer inputs for deadlines
def check_positive(value):
    ivalue = int(value)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
    return ivalue


parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
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
    default="https://sofafeed.macadmins.io/v1/macos_data_feed.json",
    const="https://sofafeed.macadmins.io/v1/macos_data_feed.json",
    nargs="?",
    metavar="URL or path",
    help="Full path or URL to a SOFA-generated macos_data_feed.json file. Defaults to https://sofafeed.macadmins.io/v1/macos_data_feed.json",
)

parser.add_argument(
    "--timestamp",
    default="https://sofafeed.macadmins.io/v1/timestamp.json",
    const="https://sofafeed.macadmins.io/v1/timestamp.json",
    nargs="?",
    metavar="URL or path",
    help="Full path or URL to a SOFA-generated timestamp.json file. Defaults to https://sofafeed.macadmins.io/v1/timestamp.json",
)

parser.add_argument(
    "--excludegroup",
    nargs="+",
    metavar="Excluded Group Name",
    help="Name of a Smart Computer Group containing devices to EXCLUDE from automated updates (such as conference room devices)",
)

parser.add_argument(
    "--overridegroup",
    nargs="+",
    metavar="Override Group Name",
    help="Name of a Smart Computer Group to target for updates (overrides default outdated group)",
)

parser.add_argument(
    "--canarygroup",
    nargs="+",
    metavar="Canary Group Name",
    help="Name of a Smart Computer Group containing devices to always receive a 2-day installation deadline",
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
    help="Force the update to all outdated devices with the specified deadline (in days)",
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
    help="Force the update to all outdated devices with the specified deadline (in days)",
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

parser.add_argument("--version", action="version", version=f"{scriptVersion}")

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

nvdToken = args.nvdtoken if "nvdtoken" in args else os.environ.get("nvdToken", None)
vulncheckToken = (
    args.vulnchecktoken
    if "vulnchecktoken" in args
    else os.environ.get("vulncheckToken", None)
)

excludedGroupName = " ".join(args.excludegroup) if "excludegroup" in args else None
overrideGroupName = " ".join(args.overridegroup) if "overridegroup" in args else None

canaryGroupName = " ".join(args.canarygroup) if "canarygroup" in args else None
canaryVersion = args.canaryversion.replace('"', "") if "canaryversion" in args else None
canaryOK = args.canaryok if "canaryok" in args else False

canaryDays = args.canarydeadline
urgentDays = args.urgentdeadline
standardDays = args.deadline
forceDays = args.force if "force" in args else None

debug = args.debug if "debug" in args else None
dryrun = args.dryrun if "dryrun" in args else None

###############################
#### Logging configuration ####
###############################

## Local log file
logFile = NamedTemporaryFile(suffix=".log").name

## Configure root logger
logger = logging.getLogger()
logger.handlers = []

## Create handlers
logToFile = logging.FileHandler(str(logFile))
logToConsole = logging.StreamHandler(sys.stdout)

## Configure logging level and format
if debug:
    logLevel = logging.DEBUG
    logFormat = logging.Formatter(
        "[%(asctime)s %(filename)s->%(funcName)s():%(lineno)s]%(levelname)s: %(message)s"
    )
else:
    logLevel = logging.INFO
    logFormat = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

## Set root and handler logging levels
logger.setLevel(logLevel)
logToFile.setLevel(logLevel)
logToConsole.setLevel(logLevel)

## Set log format
logToFile.setFormatter(logFormat)
logToConsole.setFormatter(logFormat)

## Add handlers to root logger
logger.addHandler(logToFile)
logger.addHandler(logToConsole)

## Set up jamf sdk logger
jamfLogger = logging.getLogger("jamf_pro_sdk")
jamfLogger.handlers = []
jamfLogger.addHandler(logToFile)
jamfLogger.addHandler(logToConsole)

###############################


def endRun(exitCode=None, logLevel="info", message=None):
    if str(exitCode).isdigit():
        exitCode = int(exitCode)

    logCmd = getattr(logging, logLevel, "info")

    logCmd(message)
    sys.exit(exitCode)


## Load feed file
if feedSource := args.feedsource:
    logging.debug(f"Attempting to fetch macOS data feed from {feedSource}...")

    try:
        if feedSource.startswith("http://") or feedSource.startswith("https://"):
            feedData = json.loads(requests.get(feedSource).content)

        elif Path(feedSource).exists:
            feedData = json.loads(Path(feedSource).read_text())
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

        elif Path(timestampSource).exists:
            timestampData = json.loads(Path(timestampSource).read_text())
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
    logging.debug(f"Loading json data from {str(jsonPath)}")
    jsonData = json.loads(jsonPath.read_text())
    return jsonData


## Dump data into a json file
def dumpJson(jsonData, jsonPath):
    logging.debug(f"Dumping json data to {str(jsonPath)}")
    logging.debug(f"json data sent: {jsonData}")
    jsonPath.write_text(json.dumps(jsonData))


def sendNotifications():
    pass


def getSupportedModels():
    pass


def getCVEDetails(vulnSource, cveID, requestHeaders):

    if not cveID:
        logging.error("No CVE ID provided, unable to get details")
        return None

    if not re.match(r"^CVE-\d{4}-\d+$", cveID, re.IGNORECASE) or type(cveID) is not str:
        logging.error(f"{cveID} does not appear to be a valid CVE ID!")
        return None

    if vulnSource == "vulncheck":
        checkURL = "https://api.vulncheck.com/v3/index/nist-nvd2?cve="

    else:
        checkURL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

    logging.debug(f"Checking NVD for details on CVE {cveID}...")
    cveCheckResponse = requests.get(checkURL + cveID, headers=requestHeaders)

    cveResponseContent = cveCheckResponse.json()

    if not cveCheckResponse.ok:
        logging.error(
            f"Error occured checking for CVE details. Received return code {cveCheckResponse.status_code}"
        )
        return None

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

    logging.debug(f"CVE data: {cveData}")

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

    return cveDetails


def parseVulns(cveList):

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
        cveData = getCVEDetails(vulnSource, cve, requestHeaders)

        exploitabilityScore = cveData.get("exploitabilityScore")
        impactScore = cveData.get("impactScore")

        if not all([exploitabilityScore, impactScore]):
            logging.warning(
                f"No CVE metrics found for {cve}, excluding from average calculation"
            )
            cveCount -= 1

        else:
            logging.debug(
                f"CVE {cve}: Exploitability = {exploitabilityScore}, Impact = {impactScore}"
            )

        totalExploitabilityScore += exploitabilityScore
        totalImpactScore += impactScore

        if standoffTime > 0:
            logging.debug(f"Waiting {standoffTime} seconds before next request...")
            time.sleep(standoffTime)

    averageExploitabilityScore = round(totalExploitabilityScore / cveCount, 1)
    averageImpactScore = round(totalImpactScore / cveCount, 1)

    logging.debug(f"Average exploitability score: {averageExploitabilityScore}")
    logging.debug(f"Average impact score: {averageImpactScore}")

    if averageExploitabilityScore > 6 or averageImpactScore > 8:
        logging.info(
            f"Average scores have tripped the risk threshold--forcing shorter installation deadline!"
        )
        return True

    else:
        logging.info(
            "Average exploitability and impact scores are within normal risk ranges. No accelerated deadline required."
        )
        return False


def sendDeclarationToGroup(groupID, deadlineDays, osVersion):
    logging.info(
        f"Sending DDM update for macOS {osVersion} to group ID {groupID} with a {deadlineDays} day installation window..."
    )

    deadlineDate = datetime.now() + timedelta(days=deadlineDays)

    if deadlineDate.isoweekday() in set((6, 7)):
        logging.info(
            "Configured deadline falls on a weekend--moving to the following Monday"
        )
        deadlineDate += timedelta(days=8 - deadlineDate.isoweekday())

    installDeadlineString = datetime.strftime(deadlineDate, "%Y-%m-%dT19:00:00")

    delcarationConfig = {
        "group": {"groupId": groupID, "objectType": "COMPUTER_GROUP"},
        "config": {
            "updateAction": "DOWNLOAD_INSTALL_SCHEDULE",
            "versionType": "LATEST_ANY",
            # "versionType": "SPECIFIC_VERSION",
            # "specificVersion": str(osVersion),
            "forceInstallLocalDateTime": installDeadlineString,
        },
    }

    if not dryrun:
        logging.info("Sending declaration payload...")
        declarationResult = jamfClient.pro_api_request(
            "post", "v1/managed-software-updates/plans/group", data=delcarationConfig
        )

        if declarationResult.status_code == 201:
            logging.info("macOS update declaration was successfully sent")
            return installDeadlineString

        else:
            logging.error("Something went wrong creating the update declaration plan")
            return False

    else:
        logging.info(f"DRY RUN: DDM payload to be sent: {delcarationConfig}")

        return installDeadlineString


def getComputerGroupData(groupID=None, groupName=None):

    if groupID:
        endpointType = "id"
        query = groupID

    elif groupName:
        endpointType = "name"
        query = groupName

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
    except:
        logging.warning("Computer group not found!")
        return False


def createOrUpdateSmartGroup(groupData, groupID=None):

    if not dryrun:

        if groupID:
            logging.info(f"Updating computer group {groupID}...")
            jamfClient.classic_api.update_smart_computer_group_by_id(groupID, groupData)

            time.sleep(2)

            updatedGroupData = getComputerGroupData(groupID)

            newCriteria = updatedGroupData.criteria

            if newCriteria == groupData.criteria:
                groupResult = groupID

            else:
                groupResult = None

        else:
            logging.info(f"Creating new computer group {groupData.name}...")
            groupResult = jamfClient.classic_api.create_computer_group(groupData)

        if int(groupResult):
            logging.info("Group operation completed successfully")
            return groupResult

        else:
            logging.error(
                "Something went wrong creating or updating the computer group"
            )
            return False

    else:

        if groupID:
            logging.info(
                f"DRY RUN: Updating smart group {groupID}. Updated group data: {groupData}"
            )
            groupResult = groupID

        else:
            logging.info(f"DRY RUN: Creating new smart group with data: {groupData}")
            groupResult = 0

        return groupResult


def run():

    logging.debug("Validating run conditions...")

    if not all([jamfURL, jamfClientID, jamfClientSecret]):
        endRun(1, "critical", "Jamf Pro URL and/or credentials not found!")

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
            "critical",
            f"Feed data hash {dataHash} does not match hash found in timestamp data ({timestampHash})! Verify your SOFA feed.",
        )

    logging.info("Parsing the latest SOFA feed for macOS updates...")

    versionData = feedData.get("OSVersions")[0]
    latestVersionData = versionData.get("Latest")

    productVersion = latestVersionData.get("ProductVersion")
    buildVersion = latestVersionData.get("Build")
    releaseDate = latestVersionData.get("ReleaseDate")

    securityURL = latestVersionData.get("SecurityInfo")
    cveList = latestVersionData.get("CVEs").keys()
    exploitedCVEs = latestVersionData.get("ActivelyExploitedCVEs")

    if len(cveList) > 0:
        highRiskUpdate = parseVulns(cveList)
    else:
        highRiskUpdate = False

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

    ## Configure the jamf API client
    global jamfClient

    jamfClient = JamfProClient(
        server=jamfURL,
        credentials=ApiClientCredentialsProvider(jamfClientID, jamfClientSecret),
        session_config=SessionConfig(**{"timeout": 30, "max_retries": 3}),
    )

    ## Check to ensure the target version is available via DDM from jamf
    availableUpdateData = jamfClient.pro_api_request(
        "get", "v1/managed-software-updates/available-updates"
    )

    if availableUpdateData.ok:
        macOSVersions = availableUpdateData.json().get("availableUpdates").get("macOS")

        if productVersion not in macOSVersions:
            endRun(
                1,
                "error",
                f"{productVersion} does not yet seem to be available in jamf as a managed update target. Try again later.",
            )

    else:
        endRun(
            1,
            "error",
            f"Got {availableUpdateData.status_code} back from jamf API: {availableUpdateData.content}",
        )

    if canaryGroupName:
        canaryGroupData = getComputerGroupData(groupName=canaryGroupName)

    else:
        canaryGroupData = None

    if excludedGroupName:
        excludedGroupData = getComputerGroupData(groupName=excludedGroupName)

    else:
        excludedGroupData = None

    if overrideGroupName:
        overrideGroupData = getComputerGroupData(groupName=overrideGroupName)

    else:
        overrideGroupData = None

    ## Find computer group for up to date devices
    updatedDevicesGroupName = "macOS Version Current"

    updatedDevicesGroupData = getComputerGroupData(groupName=updatedDevicesGroupName)

    ## Create or update group
    if updatedDevicesGroupData:

        existingUpdatedGroupID = updatedDevicesGroupData.id

        updatedDevicesGroupData.criteria[0].value = productVersion

    else:

        existingUpdatedGroupID = None

        upToDateGroupCriteria = computer_groups.ClassicCriterion(
            name="Operating System Version",
            priority=0,
            and_or="and",
            search_type="greater than or equal",
            opening_paren=False,
            closing_paren=False,
            value=productVersion,
        )

        updatedDevicesGroupData = computer_groups.ClassicComputerGroup(
            name=updatedDevicesGroupName,
            is_smart=True,
            criteria=[upToDateGroupCriteria],
        )

    upToDateGroupID = createOrUpdateSmartGroup(
        updatedDevicesGroupData, existingUpdatedGroupID
    )

    ## Find computer group for outdated devices
    notUpdatedDevicesGroupName = "macOS Version Not Current"

    if notUpdatedDevicesGroupData := getComputerGroupData(
        groupName=notUpdatedDevicesGroupName
    ):

        existingNotUpdatedGroupID = notUpdatedDevicesGroupData.id

    else:

        existingNotUpdatedGroupID = None

    ## Create outdated group if it doesn't exist
    notUpdatedGroupCriteria = [
        computer_groups.ClassicCriterion(
            name="Computer Group",
            priority=0,
            and_or="and",
            search_type="not member of",
            opening_paren=False,
            closing_paren=False,
            value=updatedDevicesGroupName,
        )
    ]

    ## Add canary group to exclusions if it exists
    if canaryGroupData:

        canaryCriterion = computer_groups.ClassicCriterion(
            name="Computer Group",
            priority=1,
            and_or="and",
            search_type="not member of",
            opening_paren=False,
            closing_paren=False,
            value=canaryGroupName,
        )

        notUpdatedGroupCriteria.append(canaryCriterion)

    ## Add additional group exclusion if specified
    if excludedGroupData:

        excludedGroupCriterion = computer_groups.ClassicCriterion(
            name="Computer Group",
            priority=2 if len(notUpdatedGroupCriteria) == 2 else 1,
            and_or="and",
            search_type="not member of",
            opening_paren=False,
            closing_paren=False,
            value=excludedGroupName,
        )

        notUpdatedGroupCriteria.append(excludedGroupCriterion)

    notUpdatedDevicesGroupData = computer_groups.ClassicComputerGroup(
        name=notUpdatedDevicesGroupName, is_smart=True, criteria=notUpdatedGroupCriteria
    )

    notUpdatedGroupID = createOrUpdateSmartGroup(
        notUpdatedDevicesGroupData, existingNotUpdatedGroupID
    )

    ## Recalculate updated smart groups
    if not dryrun:
        for groupID in [upToDateGroupID, notUpdatedGroupID]:
            jamfClient.pro_api_request(
                "post", f"v1/smart-computer-groups/{groupID}/recalculate"
            )

        ## Allow some time for the groups to finish recalculating
        logging.info("Waiting 60 seconds to allow groups to fully recalculate...")
        time.sleep(60)

    if forceDays:
        logging.info(f"Forced update detected--setting deadline of {forceDays} days")
        deadlineDays = forceDays
        canaryGroupData = None

    if overrideGroupData:

        logging.info(
            f"Sending update declaration to specified group: {overrideGroupName}"
        )

        planGroupId = overrideGroupData.id
        isCanary = False

    ## Send quick update plan to canary group if it exists
    elif canaryGroupData:
        if not canaryOK:

            logging.info(
                f"Sending accelerated update declaration to canary group {canaryGroupName}"
            )

            planGroupId = canaryGroupData.id
            deadlineDays = canaryDays
            isCanary = True

        else:

            if canaryVersion == productVersion:

                logging.info(
                    f"Canary version {canaryVersion} matches current, proceeding with wide deployment"
                )
                planGroupId = notUpdatedGroupID
                isCanary = False

            else:

                logging.warning(
                    f"Canary version {canaryVersion} does not match current release {productVersion}! Ending run out of an abundance of caution. Please verify your canary deployment and try again."
                )
                endRun(1)

    else:

        ## Send normal update plan to everyone but the canary group
        logging.info("Sending standard update declaration to all required devices")
        planGroupId = notUpdatedGroupID
        isCanary = False

    if updatePlanDeadline := sendDeclarationToGroup(
        planGroupId, deadlineDays, productVersion
    ):

        planData = {
            "deployedVersion": productVersion,
            "installationDeadline": updatePlanDeadline,
            "installationDeadlineEpoch": int(
                datetime.strftime(
                    datetime.strptime(updatePlanDeadline, "%Y-%m-%dT%H:%M:%S"), "%s"
                )
            ),
            "canaryDeployment": isCanary,
            "deadlineOverride": bool(forceDays),
        }

        dataReceipt = Path("/tmp/updatePlanData.json")
        dumpJson(planData, dataReceipt)


if __name__ == "__main__":
    run()
