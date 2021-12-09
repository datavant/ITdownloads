#!/bin/bash
#
# Copyright (c) 2011-2021 VMware, Inc. All rights reserved.
#
# Tool for an unattended install / upgrade of the Carbon Black Cloud (CbDefense) sensor for macOS.
#
# Serves as an example how to create custom deploy packages and setup various options to install Cb Defense PKG in unattended mode.
#
# The script can also be used as-is:
# 1. either embedded in a custom package (along with the matching PKG) and used with software deployment tool of choice,
# 2. or pushed to a target device (via a file share, file download, etc) and executed on a command line, on the target device.
#
# For maximum compatibility, always use this tool with CBCloud Install PKG for the matching sensor major.minor release,
# ideally, extracted from the same CBCloud DMG.
#
#
#
# required parameters:
# - location of CBCloud PKG file
# - CompanyCode or UserCode
#
# optional parameters:
# - Proxy Server
# - Proxy Server Creds
# - Last Attempt Proxy Server
# - Disable auto-update
# - Disable auto-update jitter
# - Pem File (cert. for the Backend Server)
# - File Upload Limit
# - Policy Name
# - User name
# - Background Scan
# - Protection
# - RateLimit
# - ConnectionLimit
# - QueueSize
# - LearningMode
# - POC
# - AllowDowngrade
# - Disable Live Response
# - HideCommandLines
# - skip 10.13+ KEXT approval check
# - use SystemExtension for event sources
# - Disable network extension in system extension mode
# - Extend approval timeouts from 3 to 60 seconds

VERSION=3.6.1.10

#options
CBC_INSTALLER=""
COMPANY_OR_USER_CODE=""

#optional args
PROXY_SERVER=""
PROXY_CREDS=""
LAST_ATTEMPT_PROXY_SERVER=""
DISABLE_AUTOUPDATE=0
DISABLE_AUTOUPDATE_JITTER=0
BACKEND_SERVER_PEM=""
FILE_UPLOAD_LIMIT="" # empty for default
POLICY_NAME=""
USER_NAME=""
BSCAN=""
PROTECTION=""
POC=""
HIDE_COMMAND_LINES=""
DISABLE_LIVE_RESPONSE=0
ALLOW_INSTALL_UPGRADE_WITHOUT_KEXT_PREAPPROVAL=0
SKIP_PKG_SIGNING_VERIFICATION=0
KERNEL_TYPE=0
PERSISTENT_KEXT=""
DISABLE_SYSEXT_NETWORK_EXTENSION=0
EXTEND_APPROVAL_TIMEOUT=0

CB_DEFENSE_ALLOW_DOWNGRADE=0

# throttle args
unset RATE_LIMIT
unset CONNECTION_LIMIT
unset QUEUE_SIZE
unset LEARNING_MODE

#other vars
LEGACY_CBD_INSTALL_TMP="/tmp/cbdefense-install"
LEGACY_CBC_INSTALL_TMP="/tmp/cbcloud-install"
CBC_INSTALL_TMP="/var/cbcloud-install"
LOG="/var/log/cbcloud-install-unattended.log"

CBC_INSTALL_LOGS_PREFIX='/tmp/cbcloud'
LEGACY_CBD_APP_INSTALL_PREFIX='/Applications/Confer.app'
CBC_APP_INSTALL_PREFIX='/Library/Application Support/com.vmware.carbonblack.cloud'

install_upgrade=''

NATIVE_ARCH="Arm"
arch_translated="$(sysctl -in sysctl.proc_translated)"
# sysctl.proc_translated returns nothing if on Intel
# sysctl.proc_translated returns 1 if under Rosetta or 0 if running natively on ARM
if [[ "${arch_translated}" != "1" && "${arch_translated}" != "0" ]]; then
    NATIVE_ARCH="Intel"
fi

function show_version()
{
  echo "${0} version ${VERSION}"
}

function usage()
{
  version=$(/usr/bin/sw_vers  | grep ProductVersion | cut -d':' -f2 | awk '{gsub(/^[ \t]+|[ \t]+$/,"");print}')
  major=$(echo "${version}" | cut -d'.' -f1)

  cat <<EOF

This tool installs or upgrades the macOS Carbon Black Cloud (Defense) sensor on this machine.

usage: ${0} options

OPTIONS:
   -h          Show this message
   -v          Show version of this script. Major and minor version should match the version of Cb Defense PKG file to be deployed.
   -i          Path to CBCloud Install.pkg (required)
   -c          Company or User Code used to register the device (required)
   -p          Proxy server and port, e.g. 10.5.6.7:54443 (optional)
   -x          Proxy credentials, if required, e.g. username:password (optional), requires -p
   -l          Last Attempt proxy server and port, used if every other connectivity method fails, e.g. 10.5.6.7:54443 (optional)
   -b          [deprecated] [optional] Backend Server address for OnPrem Install
   -m          Backend Server PEM file for OnPrem Install (optional)
   -u          Disable autoupdate (optional).  Auto-update is enabled by default.
   -t          File upload limit in MB (optional).  Default is no limit.
   -g          Policy name (optional). The policy to add the device to during registration.
   -o          User name / e-mail address override (optional). Used during registration and for identifying the device.
EOF
    if [[ ${major} -le 11 ]] && [[ ${NATIVE_ARCH} == "Intel" ]]; then
        cat <<EOF
   -k          Select Kernel Extension for kernel mode.  Default is KEXT on <=10.15 and SYSEXT on >=10.16.
EOF
    fi
cat <<EOF
   -e          Select System Extension for kernel mode.  KEXT is always used on <=10.15. SE is always used on >=12.0 and M1. Option is applied on Intel 10.16.
   -s          Background scan enable ("on") or disable ("off") (optional). Default is enabled. Cloud policy overrides this setting.
   -d          Protection after install disabled ("off") (sensor bypass mode), until reenabled later from Policy page.  This is optional.  Default is protection enabled after install.
   --downgrade=1 Allow unattended downgrade. (optional)
   --disable-upgrade-jitter=1 Disable auto-upgrade jitter (optional)
   --disable-live-response=1 Disable live response (optional)
EOF
    if [[ ${major} -le 11 ]] && [[ ${NATIVE_ARCH} == "Intel" ]]; then
        cat <<EOF
   --skip-kext-approval-check=1 (optional)  Allows for >=3.1 sensor install/upgrade to run on macOS >=10.13 even if KEXT approval has not been done prior to the install/upgrade. KEXT approval can then be deferred until after the sensor install/upgrade. Warning: macOS 11.0 requires a KEXT MDM pre-approval to install a KEXT sensor
EOF
   fi
cat <<EOF
   --enable-fips (optional) Configures the sensor for use with a FIPS-compliant backend. Required for FIPS-compliant GovCloud backends. Do not use on commercial backends.
   --enable-hide-command-lines=1 (optional) Enable hiding command lines in confer.log and event table
   --skip-pkg-signing-verification (optional) Do not verify signature of the CBCloud pkg before running the installer. NOT RECOMMENDED.
   --disable-sysext-network-extension (optional) Disable network extension. Only available in SystemExtension mode, macOS 11.00 and higher. Network extension is enabled by default.
   --extend-approval-timeout (optional) Extends approval timeouts for System Extension from 3 seconds to 60 seconds. Only available in System Extension mode, macOS 11.0 and higher.
   --policy-name (optional) The policy to add the device to during registration.

Network Throttle Advanced Options (optional)
   --ratelimit
   --connectionlimit
   --queuesize
   --learningmode

Demo-mode only options (optional):
   --enable-poc POC fast startup (optional). Default is disabled.

EOF
    if [[ ${major} -le 11 ]] && [[ ${NATIVE_ARCH} == "Intel" ]]; then
        cat <<EOF
   The following sensor settings are applicable at sensor upgrade:
   [KernelType] : Use (-e) to switch from KEXT to SYSEXT mode, and (-k) to switch from SYSEXT to KEXT mode.
EOF
   fi
cat <<EOF

EXAMPLES:
    ${0} -i /tmp/CBCloud Install.pkg -c 652797N7
    ${0} -i /tmp/CBCloud Install.pkg -c 652797N7 -p 10.0.3.3:123
    ${0} -i /tmp/CBCloud Install.pkg -c 652797N7 -p 10.0.3.3:123 -x myproxyuser:myproxypassword
    ${0} -i /tmp/CBCloud Install.pkg -c 652797N7 -u
    ${0} -i /tmp/CBCloud Install.pkg -c 652797N7 --downgrade=1
    ${0} -i /tmp/CBCloud Install.pkg -c 652797N7 -u -m /tmp/mycompany.pem
    ${0} -i /tmp/CBCloud Install.pkg -c 652797N7 -u -t 12 -s off -d off
    ${0} -i /tmp/CBCloud Install.pkg -c 652797N7 -g 'Administrators' -o 'adminuser2'
    ${0} -i /tmp/CBCloud Install.pkg -c 652797N7 --learningmode=30
EOF
    if [[ ${major} -le 11 ]] && [[ ${NATIVE_ARCH} == "Intel" ]]; then
        cat <<EOF
    ${0} -i /tmp/CBCloud Install.pkg -c 652797N7 --skip-kext-approval-check=1
EOF
    fi
cat <<EOF
    ${0} -i /tmp/CBCloud Install.pkg -c 652797N7 --skip-pkg-signing-verification=1
    ${0} -i /tmp/CBCloud Install.pkg -c 652797N7 --disable-sysext-network-extension=1
    ${0} -i /tmp/CBCloud Install.pkg -c 652797N7 --extend-approval-timeout=1
EOF

}


### log options run

touch "${LOG}"
date >> "${LOG}"
echo "Running with options: $*" >> "${LOG}"

### parse options

while getopts "hket:vt:i:c:p:l:x:b:m:s:t:g:o:d:u-:" OPTION
do
  case $OPTION in
    h)
      usage
      exit 1
      ;;
    v)
      show_version
      exit 0
      ;;
    i)
      CBC_INSTALLER=${OPTARG}
      ;;
    c)
      COMPANY_OR_USER_CODE=${OPTARG}
      ;;
    p)
      PROXY_SERVER=${OPTARG}
      ;;
    x)
      PROXY_CREDS=${OPTARG}
      ;;
    l)
      LAST_ATTEMPT_PROXY_SERVER=${OPTARG}
      ;;
    b)
      #deprecated
      ;;
    m)
      BACKEND_SERVER_PEM=${OPTARG}
      ;;
    s)
      BSCAN=${OPTARG}
      ;;
    t)
      FILE_UPLOAD_LIMIT=${OPTARG}
      ;;
    g)
      POLICY_NAME=${OPTARG}
      ;;
    o)
      USER_NAME=${OPTARG}
      ;;
    u)
      DISABLE_AUTOUPDATE=1
      ;;
    k)
      KERNEL_TYPE=1
      ;;
    e)
      KERNEL_TYPE=2
      ;;
    d)
      PROTECTION=${OPTARG}
      ;;

    -)
      case "${OPTARG}" in
        downgrade)
          val="${!OPTIND}"; OPTIND=$(( OPTIND + 1 ))
          CB_DEFENSE_ALLOW_DOWNGRADE=1
          ;;

        downgrade=*)
          CB_DEFENSE_ALLOW_DOWNGRADE=1
          ;;

        disable-upgrade-jitter)
          val="${!OPTIND}"; OPTIND=$(( OPTIND + 1 ))
          DISABLE_AUTOUPDATE_JITTER=1
          ;;

        disable-upgrade-jitter=*)
          DISABLE_AUTOUPDATE_JITTER=1
          ;;

        disable-live-response)
          val="${!OPTIND}"; OPTIND=$(( OPTIND + 1 ))
          DISABLE_LIVE_RESPONSE=1
          ;;

        disable-live-response=*)
          DISABLE_LIVE_RESPONSE=1
          ;;

        ratelimit)
          val="${!OPTIND}"; OPTIND=$(( OPTIND + 1 ))
          RATE_LIMIT=${val}
          ;;

        ratelimit=*)
          val=${OPTARG#*=}
          RATE_LIMIT=${val}
          ;;

        connectionlimit)
          val="${!OPTIND}"; OPTIND=$(( OPTIND + 1 ))
          CONNECTION_LIMIT=${val}
          ;;

        connectionlimit=*)
          val=${OPTARG#*=}
          CONNECTION_LIMIT=${val}
          ;;


        queuesize)
          val="${!OPTIND}"; OPTIND=$(( OPTIND + 1 ))
          QUEUE_SIZE=${val}
          ;;

        queuesize=*)
          val=${OPTARG#*=}
          QUEUE_SIZE=${val}
          ;;

        learningmode)
          val="${!OPTIND}"; OPTIND=$(( OPTIND + 1 ))
          LEARNING_MODE=${val}
          ;;

        learningmode=*)
          val=${OPTARG#*=}
          LEARNING_MODE=${val}
          ;;

        persistent-kext=*)
          val=${OPTARG#*=}
          PERSISTENT_KEXT=${val}
          ;;

        enable-fips)
          ENABLE_FIPS=1
          ;;

        enable-fips=*)
          val=${OPTARG#*=}
          ENABLE_FIPS=${val}
          ;;

        enable-poc)
          val="${!OPTIND}"; OPTIND=$(( OPTIND + 1 ))
          POC='on'
          ;;

        enable-poc=*)
          val=${OPTARG#*=}
          POC=${val}
          ;;

        enable-hide-command-lines)
          val="${!OPTIND}"; OPTIND=$(( OPTIND + 1 ))
          HIDE_COMMAND_LINES=1
          ;;

        enable-hide-command-lines=*)
          val=${OPTARG#*=}
          HIDE_COMMAND_LINES=${val}
        ;;

        skip-kext-approval-check)
          ALLOW_INSTALL_UPGRADE_WITHOUT_KEXT_PREAPPROVAL=1
          ;;
        skip-kext-approval-check=*)
          val=${OPTARG#*=}
          ALLOW_INSTALL_UPGRADE_WITHOUT_KEXT_PREAPPROVAL=${val}
          ;;

        skip-pkg-signing-verification)
          SKIP_PKG_SIGNING_VERIFICATION=1
          ;;
        skip-pkg-signing-verification=*)
          val=${OPTARG#*=}
          SKIP_PKG_SIGNING_VERIFICATION=${val}
          ;;

        disable-sysext-network-extension)
          DISABLE_SYSEXT_NETWORK_EXTENSION=1
          ;;
        disable-sysext-network-extension=*)
          val=${OPTARG#*=}
          DISABLE_SYSEXT_NETWORK_EXTENSION=${val}
          ;;

        extend-approval-timeout)
          EXTEND_APPROVAL_TIMEOUT=1
          ;;
        extend-approval-timeout=*)
          val=${OPTARG#*=}
          EXTEND_APPROVAL_TIMEOUT=${val}
          ;;
        policy-name)
          val="${!OPTIND}"; OPTIND=$(( OPTIND + 1 ))
          POLICY_NAME=${val}
          ;;
        policy-name=*)
          val=${OPTARG#*=}
          POLICY_NAME=${val}
          ;;
        *)
          if [ "$OPTERR" = 1 ] && [ "${optspec:0:1}" != ":" ]; then
            echo "ERROR: Unknown long option --${OPTARG}" >&2
            usage
            exit
          fi
          ;;
      esac ;;
    ?)
      echo "Invalid option: -${OPTARG}"
      usage
      exit
      ;;
  esac
done


function print_vals() {
  echo "CBC_INSTALLER=${CBC_INSTALLER}"
  echo "COMPANY_OR_USER_CODE=${COMPANY_OR_USER_CODE}"
  echo "PROXY_SERVER=${PROXY_SERVER}"
  echo "PROXY_CREDS=${PROXY_CREDS}"
  echo "LAST_ATTEMPT_PROXY_SERVER=${LAST_ATTEMPT_PROXY_SERVER}"
  echo "BACKEND_SERVER_PEM=${BACKEND_SERVER_PEM}"
  echo "DISABLE_AUTOUPDATE=${DISABLE_AUTOUPDATE}"
  echo "DISABLE_AUTOUPDATE_JITTER=${DISABLE_AUTOUPDATE_JITTER}"
  echo "FILE_UPLOAD_LIMIT=${FILE_UPLOAD_LIMIT}"
  echo "POLICY_NAME=${POLICY_NAME}"
  echo "USER_NAME=${USER_NAME}"
  echo "BSCAN=${BSCAN}"
  echo "PROTECTION=${PROTECTION}"
  echo "RATE_LIMIT=${RATE_LIMIT}"
  echo "CONNECTION_LIMIT=${CONNECTION_LIMIT}"
  echo "QUEUE_SIZE=${QUEUE_SIZE}"
  echo "LEARNING_MODE=${LEARNING_MODE}"
  echo "POC=${POC}"
  echo "KERNEL_TYPE=${KERNEL_TYPE}"
  echo "PERSISTENT_KEXT=${PERSISTENT_KEXT}"
  echo "DISABLE_LIVE_RESPONSE=${DISABLE_LIVE_RESPONSE}"
  echo "CB_DEFENSE_ALLOW_DOWNGRADE=${CB_DEFENSE_ALLOW_DOWNGRADE}"
  echo "ALLOW_INSTALL_UPGRADE_WITHOUT_KEXT_PREAPPROVAL=${ALLOW_INSTALL_UPGRADE_WITHOUT_KEXT_PREAPPROVAL}"
  echo "HIDE_COMMAND_LINES=${HIDE_COMMAND_LINES}"
  echo "DISABLE_SYSEXT_NETWORK_EXTENSION=${DISABLE_SYSEXT_NETWORK_EXTENSION}"
  echo "EXTEND_APPROVAL_TIMEOUT=${EXTEND_APPROVAL_TIMEOUT}"
  echo "NATIVE_ARCH=${NATIVE_ARCH}"
  echo "ENABLE_FIPS=${ENABLE_FIPS}"
}


function validate_options() {

  #print_vals

  ###validate options
  if [[ -z ${CBC_INSTALLER} ]] || [[ -z ${COMPANY_OR_USER_CODE} ]] ; then
    echo "ERROR: Path to CBCloud PKG file and company or user code are required parameters"
    usage
    exit 1
  fi
  if [[ ${#COMPANY_OR_USER_CODE} -lt 8 ]]; then
    echo "ERROR: Please enter the user or company code as specified in the backend"
    exit 1
  fi

  #proxy
  if [[ -n ${PROXY_CREDS} ]] ; then
    # check for required option
    if [[ -z ${PROXY_SERVER} ]] ; then
      usage
      exit 1
    fi

  fi

  # backend
  # if PEM, need server
  if [[ -n ${BACKEND_SERVER_PEM} ]] ; then
    # check for required file
    if [[ ! -f "${BACKEND_SERVER_PEM}" ]] ; then
      echo "ERROR: Backend server PEM file not found: ${BACKEND_SERVER_PEM}"
      exit 2
    fi
  fi
}


function validate_hs_kext_approval() {

  echo -n "KEXT check: macOS >=10.13 detected, checking KEXT pre-approval..."

  version=$(/usr/bin/sw_vers  | grep ProductVersion | cut -d':' -f2 | awk '{gsub(/^[ \t]+|[ \t]+$/,"");print}')
  major=$(echo "${version}" | cut -d'.' -f1)

  # Perform KEXT pre-approval check if: 1) the flag was set to '', or 2) the flag wasn't used (or was set to 0) and
  # kernel type is KEXT, or 3) the flag wasn't used (or was set to 0) and kernel type is DEFAULT and macOS is version 10.*
  if [[ -z ${ALLOW_INSTALL_UPGRADE_WITHOUT_KEXT_PREAPPROVAL} ]] || [[ ${ALLOW_INSTALL_UPGRADE_WITHOUT_KEXT_PREAPPROVAL} -eq 0 ]] && { [[ ${KERNEL_TYPE} -eq 1 ]] || { [[ ${KERNEL_TYPE} -eq 0 ]] && [[ ${major} -eq 10 ]];};}; then

    # Perform KEXT pre-approval check.
    # NOTE: Apple does not currently provide a solid API to check this.
    # The mechanism utilized here relies on internal schemas and is "best-effort" check, until Apple provides a better interface.
    # If the queries appear no longer working, the internal mechanism of KEXT approval tracking may have changed, and the approval status may be unknown.
    # The queries also do not take into account other mechanisms of KEXT approval (entire SIP disablement, etc)
    # In such cases of KEXT approval status being unknown, the override flag is still required for safety.

    KEXT_TEAM_ID_31='7AGZNQ2S2T'
    KEXT_BUNDLE_ID_31='com.carbonblack.defense.kext'
    KEXT_POLICY_DB_INTERNAL='/var/db/SystemPolicyConfiguration/KextPolicy' #internal
    DB_CMD='/usr/bin/sqlite3'

    kext_approval_unknown=0
    kext_approved=0

    # Check to see if db_cmd exists
    if [ ! -f ${DB_CMD} ] ; then
      echo "Error: unable to check internal dbs: no ${DB_CMD}"
      kext_approval_unknown=1
    fi
    # check to see if the DBs to be queried exists
    if [ ! -f ${KEXT_POLICY_DB_INTERNAL} ] ; then
      echo "Error: unable to check internal dbs, no ${KEXT_POLICY_DB_INTERNAL}"
      kext_approval_unknown=1
    fi

    # Try to execute checks
    if [[ ${kext_approval_unknown} -eq 0 ]] ; then
      col1=team_id
      col2=bundle_id
      table1=kext_policy
      table2=kext_policy_mdm
      user_approved=$(${DB_CMD} ${KEXT_POLICY_DB_INTERNAL} "SELECT count(${col1}) FROM ${table1} WHERE ${col1}=\"${KEXT_TEAM_ID_31}\" AND ${col2}=\"${KEXT_BUNDLE_ID_31}\"" 2>/dev/null)
      # If the query fails just print a message and don't fail
      if [ ${?} -ne 0 ] ; then
        printf "Info: Could not query kext_policy table\n"
      fi
      mdm_approved=$(${DB_CMD} ${KEXT_POLICY_DB_INTERNAL} "SELECT count(${col1}) FROM ${table2} WHERE ${col1}=\"${KEXT_TEAM_ID_31}\" AND ${col2}=\"${KEXT_BUNDLE_ID_31}\"" 2>/dev/null)
      if [ ${?} -ne 0 ] ; then
        printf "Info: Could not query kext_policy_mdm table\n"
      fi
    fi

    # Evaluate if KEXT is preapproved
    # A failed query, non-zero return is not necessarilly a fauilure if the other succeeded
    if [[ -n ${user_approved} ]] && [[ ${user_approved} -gt 0 ]] ; then
      kext_approved=1
      echo "...OK (user pre-approved)"
    fi
    if [[ -n ${mdm_approved} ]] && [[ ${mdm_approved} -gt 0 ]] ; then
      kext_approved=1
      echo "...OK (MDM pre-approved)"
    fi

    if [ ${kext_approved} -eq 0 ] ; then
      echo "Error: KEXT does not appear to be pre-approved on this device by MDM or user."
      cat <<EOF

Exiting the sensor ${install_upgrade} because KEXT pre-approval was not detected.
Please use one of the following options to work around this:

1. (Preferred) Pre-approve KEXT on macOS 10.13+ devices prior to the sensor ${install_upgrade}. Refer to KB and use your preferred KEXT approval method for the following Cb Defense KEXT IDs:
- KEXT bundle ID: ${KEXT_BUNDLE_ID_31}
- KEXT team ID: ${KEXT_TEAM_ID_31}

Using this option will ensure that Carbon Black Cloud sensor version ${VERSION} remains fully operational immediately after the ${install_upgrade}.

2. Optionally, you can defer the KEXT approval until shortly after the sensor ${install_upgrade}. Note, that sensors on devices with unapproved KEXT will automatically transition into the disabled (bypass) state immediately after the ${install_upgrade}. Please ensure that KEXT approval procedure follows. Sensors will then re-enable themselves within 30 mins after the deferred KEXT approval.  In order to use this option, use the --skip-kext-approval-check switch to proceed with the ${install_upgrade} and approve KEXT at later time.

EOF
      exit 9
    fi
  else
    echo "...SKIP (--skip-kext-approval-check is used)"
    echo "Please ensure to approve the Cb Defense KEXT shortly after the sensor ${install_upgrade}."
  fi

}

function validate_run() {

  ###validate OS
  os=$(uname)
  if [[ ${os} != 'Darwin' ]] ; then
    echo "ERROR: Unsupported OS, required macOS 10.15 or later"
    exit 3
  fi

  ###check the actual version
  ###Note: installer will do that for us, but in the unattended mode, the message would be obscured
  version=$(/usr/bin/sw_vers  | grep ProductVersion | cut -d':' -f2 | awk '{gsub(/^[ \t]+|[ \t]+$/,"");print}')
  major=$(echo "${version}" | cut -d'.' -f1)
  minor=$(echo "${version}" | cut -d'.' -f2)
  patch=$(echo "${version}" | cut -d'.' -f3)

  if [[ -n ${version} ]] ; then
    echo -n "Detected macOS version: ${major}.${minor}.${patch}..."

    if [[ ${major} -lt 10 ]] ||
    { [[ ${major} -eq 10 ]] && [[ ${minor} -lt 15 ]] ; } ; then
      echo "ERROR: Unsupported OS, required macOS 10.15 or later"
      exit 3
    fi

    if [[ (${major} -gt 12) ]]; then
      echo "WARNING: This OS is newer than the sensor being installed, proceeding with install. Please refer to https://community.carbonblack.com/t5/Documentation-Downloads/Carbon-Black-Cloud-sensor-macOS-support/ta-p/66268 for more information."
    else
      echo "...OK"
    fi
  fi

  # KernelType
  if [[ ${KERNEL_TYPE} -eq 2 ]] ; then
	if  [[ ((${major} -eq 10  && ${minor} -lt 15)) ]] ; then
            echo "Unsupported OS for System Extension option, required macOS 10.15+. Installing KEXT sensor instead"
            KERNEL_TYPE=0
        fi
  fi

  if [[ ${KERNEL_TYPE} -eq 1 ]] ; then
        if [[ (${major} -ge 12) ]] || [[ ${NATIVE_ARCH} != "Intel" ]] ; then
            # Sensor will install in System Extension mode.
            KERNEL_TYPE=2
        fi
  fi

  ###validate install framework
  if [[ ! -x /usr/sbin/installer ]] ; then
    echo "ERROR: Installer framework not found"
    exit 4
  fi

  ###validate privileges
  user=$(whoami)
  if [[ ${user} != "root" ]] ; then
    echo "ERROR: root privileges are required to install the Carbon Black Cloud sensor."
    #setup
    exit 1
  fi


  ###validate pkg
  if [[ ! -f "${CBC_INSTALLER}" ]] ; then
    echo "ERROR: Carbon Black Cloud Installer ${CBC_INSTALLER} file not found"
    exit 2
  fi

  ###validate pkg is CbDefense on OSX > 10.6 (need pkgutil support)
  if [[ ${major} -ge 10 && ${minor} -gt 6 && ${SKIP_PKG_SIGNING_VERIFICATION} -eq 0 ]] ; then
    if [[ -x /usr/sbin/pkgutil ]] ; then
      err=$(/usr/sbin/pkgutil --check-signature "${CBC_INSTALLER}" | grep '(JA7945SK43)')
      er=$?
      if [[ ${er} -ne 0 ]] ; then
        err=$(/usr/sbin/pkgutil --check-signature "${CBC_INSTALLER}" | grep '(7AGZNQ2S2T)')
        er=$?
        if [[ ${er} -ne 0 ]] ; then
          echo "ERROR: Carbon Black Cloud Installer cannot be verified: $err:$er"
          exit 3
        fi
      fi
    fi
  fi

  ### KEXT approval safe-guard check on macOS >=10.13
  if [[ ((${major} -eq 10  &&  ${minor} -ge 13) || (${major} -lt 12)) && ${KERNEL_TYPE} != 2 ]] ; then
    validate_hs_kext_approval
  fi

  echo "Compatibility validation OK."

}

function init() {
  echo
  echo "Running tool: ${0}, version ${VERSION}."
  echo "For maximum compatibility, ensure to use this tool for installing or upgrading to a matching ${VERSION} version of the corresponding CBCloud PKG. Both the tool and the PKG should be extracted from the same CBCloud DMG ${VERSION}."
  echo
if [ -f "${LEGACY_CBD_APP_INSTALL_PREFIX}/cfg.ini" ] || [ -f "${CBC_APP_INSTALL_PREFIX}/Config/cfg.ini" ]; then
    install_upgrade='upgrade'
    echo "Previous sensor installation detected."
  else
    install_upgrade='installation'
    echo "Fresh sensor installation."
  fi

}

function setup() {
  ###remove legacy tmps just in case
  rm -rf ${LEGACY_CBD_INSTALL_TMP}
  rm -rf ${LEGACY_CBC_INSTALL_TMP}
  ###setup temp
  rm -rf ${CBC_INSTALL_TMP}
  mkdir -p ${CBC_INSTALL_TMP}
  ###setup ini

  tmp_cfg_ini="${CBC_INSTALL_TMP}/cfg.ini"
  tmp_params="${CBC_INSTALL_TMP}/params"
  tmp_customer_pem="${CBC_INSTALL_TMP}/customer.pem"
  echo "[customer]" > "${tmp_cfg_ini}"

  echo "Code=${COMPANY_OR_USER_CODE}" >> "${tmp_cfg_ini}"

  # Proxy
  if [[ -n ${PROXY_SERVER} ]] ; then
    echo "Option: using Proxy Server: ${PROXY_SERVER}."
    echo "ProxyServer=${PROXY_SERVER}" >> "${tmp_cfg_ini}"
  fi

  if [[ -n ${PROXY_CREDS} ]] ; then
    echo "Option: using Proxy Creds."
    echo "ProxyServerCredentials=${PROXY_CREDS}" >> "${tmp_cfg_ini}"
  fi

  # Last Attempt Proxy
  if [[ -n ${LAST_ATTEMPT_PROXY_SERVER} ]] ; then
    echo "Option: using Last Attempt Proxy Server: ${LAST_ATTEMPT_PROXY_SERVER}."
    echo "LastAttemptProxyServer=${LAST_ATTEMPT_PROXY_SERVER}" >> "${tmp_cfg_ini}"
  fi


  # onPrem server
  if [[ -n ${BACKEND_SERVER_PEM} ]] ; then
    echo "Option: using OnPrem backend server PEM: ${BACKEND_SERVER_PEM}."
    cp -f "${BACKEND_SERVER_PEM}" "${tmp_customer_pem}"
    if [[ ! -f "${tmp_customer_pem}" ]] ; then
      echo "ERROR: could not copy customer.pem"
      exit 5
    fi
    echo "PemFile=customer.pem" >> "${tmp_cfg_ini}"
  fi


  # no AutoUpdate
  if [[ ${DISABLE_AUTOUPDATE} -eq 1 ]] ; then
    echo "Option: sensor cloud upgrade is disabled."
    echo "AutoUpdate=false" >> "${tmp_cfg_ini}"
  fi

  # no AutoUpdate jitter
  if [[ ${DISABLE_AUTOUPDATE_JITTER} -eq 1 ]] ; then
    echo "Option: sensor cloud upgrade jitter is disabled."
    echo "AutoUpdateJitter=false" >> "${tmp_cfg_ini}"
  fi


  # protection
  if [[ -n ${PROTECTION} ]] ; then
    if [[ ${PROTECTION} == 'off' ]] || [[ ${PROTECTION} == 'false' ]] ; then
      echo "Option: disabling protection after install. Group policy can override this."
      echo "InstallBypass=true" >> "${tmp_cfg_ini}"
    else
      echo "Option: Protection: using the default (enabled). Group policy can override this."
    fi
  else
    echo "Option: Protection: using the default (enabled). Group policy can override this."
  fi

  # upload limit (currently deprecated setting)
  if [[ -n ${FILE_UPLOAD_LIMIT} ]] ; then

    if [[ ${FILE_UPLOAD_LIMIT} -gt 0 ]] ; then
      echo "Option: using file upload limit: ${FILE_UPLOAD_LIMIT} (deprecated)."
      echo "FileUploadLimit=${FILE_UPLOAD_LIMIT}" >> "${tmp_cfg_ini}"
    elif [[ ${FILE_UPLOAD_LIMIT} -eq 0 ]] ; then
      echo "FileUploadLimit=0" >> "${tmp_cfg_ini}"
    fi
  fi

  # policy name
  if [[ -n ${POLICY_NAME} ]] ; then
    echo "Option: using register policy name: ${POLICY_NAME}."
    echo "PolicyName=${POLICY_NAME}" >> "${tmp_cfg_ini}"
  fi

  # user name
  if [[ -n ${USER_NAME} ]] ; then
    echo "Option: using register user name: ${USER_NAME}."
    echo "EmailAddress=${USER_NAME}" >> "${tmp_cfg_ini}"
  fi

  # background scan
  if [[ -n ${BSCAN} ]] ; then
    if [[ ${BSCAN} == 'on' ]] || [[ ${BSCAN} == 'true' ]] ; then
      echo "Option: enabling background scan."
      echo "BackgroundScan=true" >> "${tmp_cfg_ini}"
    elif [[ ${BSCAN} == 'off' ]] || [[ ${BSCAN} == 'false' ]] ; then
      echo "Option: disabling background scan."
      echo "BackgroundScan=false" >> "${tmp_cfg_ini}"
    else
      echo "Option: invalid background scan setting: ${BSCAN}, using the default (off)."
    fi
  else
    echo "Option: Background scan: using the default (enabled). Group policy can override this."
  fi


  # rate-limit
  if [[ -n ${RATE_LIMIT} ]] ; then
    echo "Option: using RateLimit: ${RATE_LIMIT}."
    echo "RateLimit=${RATE_LIMIT}" >> "${tmp_cfg_ini}"
  fi

  # connection-limit
  if [[ -n ${CONNECTION_LIMIT} ]] ; then
    echo "Option: using ConnectionLimit: ${CONNECTION_LIMIT}."
    echo "ConnectionLimit=${CONNECTION_LIMIT}" >> "${tmp_cfg_ini}"
  fi

  # queue-size
  if [[ -n ${QUEUE_SIZE} ]] ; then
    echo "Option: using QueueSize: ${QUEUE_SIZE}."
    echo "QueueSize=${QUEUE_SIZE}" >> "${tmp_cfg_ini}"
  fi

  # learning-mode
  if [[ -n ${LEARNING_MODE} ]] ; then
    echo "Option: using LearningMode: ${LEARNING_MODE}."
    echo "LearningMode=${LEARNING_MODE}" >> "${tmp_cfg_ini}"
  fi

  # POC
  if [[ -n ${POC} ]] ; then
    if [[ ${POC} == 'on' ]] || [[ ${POC} == 'true' ]] || [[ ${POC} -eq 1 ]] ; then
      echo "Option: enabling POC mode."
      echo "POC=1" >> "${tmp_cfg_ini}"
    else
      echo "Option: POC: using the default (disabled)."
    fi
  fi

  # downgrade
  touch "${tmp_params}"
  if [[ ${CB_DEFENSE_ALLOW_DOWNGRADE} -eq 1 ]] ; then
    echo "Option: sensor downgrade allowed."
    echo "CB_DEFENSE_ALLOW_DOWNGRADE=1" >> "${tmp_params}"
  else
    echo "Option: sensor downgrade not allowed."
  fi

  # live response
  if [[ ${DISABLE_LIVE_RESPONSE} -eq 1 ]] ; then
    echo "Option: Live Response is disabled."
    echo "CbLRKill=true" >> "${tmp_cfg_ini}"
  fi

  # hide command lines
  if [[ -n ${HIDE_COMMAND_LINES} ]] ; then
    if [[ ${HIDE_COMMAND_LINES} -eq 1 ]] ; then
      echo "Option: enabling HIDE_COMMAND_LINES."
      echo "HideCommandLines=true" >> "${tmp_cfg_ini}"
    else
      echo "Option: disabling HIDE_COMMAND_LINES."
      echo "HideCommandLines=false" >> "${tmp_cfg_ini}"
    fi
  fi

  # disable network extension in system extension mode
  if [[ ${DISABLE_SYSEXT_NETWORK_EXTENSION} -eq 1 ]] ; then
    echo "Option: network extension is disabled."
    echo "DisableSysextNetworkExtension=true" >> "${tmp_cfg_ini}"
  fi
  
  # disable network extension in system extension mode
  if [[ ${EXTEND_APPROVAL_TIMEOUT} -eq 1 ]] ; then
    echo "Option: SE approval timeout is extended."
    echo "ExtendApprovalTimeout=true" >> "${tmp_cfg_ini}"
  fi

  # System Extension
  echo "KernelType=${KERNEL_TYPE}" >> "${tmp_cfg_ini}"
  if [[ ${install_upgrade} == 'upgrade' ]] && [[ ${KERNEL_TYPE} -gt 0 ]]; then
    cp -f "${tmp_cfg_ini}" "${tmp_cfg_ini}.upg"
    echo "Option: Will attempt to upgrade sensor setting KernelType."
  fi

  if [[ -n "${PERSISTENT_KEXT}" ]]; then
    if [[ "${PERSISTENT_KEXT}" == "1" ]]; then
      echo "Marking Kext to load persistently"
      echo "KextLoadFlags=2" >> "${tmp_cfg_ini}"
    elif [[ "${PERSISTENT_KEXT}" == "0" ]]; then
      echo "Marking Kext to be unloadable on MacOS versions below Big Sur"
      echo "KextLoadFlags=1" >> "${tmp_cfg_ini}"
    else
      echo "Unknown argument passed to --persistent-kext flag ${PERSISTENT_KEXT}"
      exit 1
    fi
  fi
  
  if [[ -n "${ENABLE_FIPS}" ]]; then
    if [[ "${ENABLE_FIPS}" -gt "0" ]]; then
      echo "Option: Enabling FIPS mode"
      echo "FipsMode=true" >> "${tmp_cfg_ini}"
    fi
  fi

}



function install() {

  ###run install / upgrade
  # run the installer in silent mode
  # it will detect fresh install case vs silent upgrade

  echo "Carbon Black Cloud sensor installation/upgrade in progress..."
  run_install_log=$(/usr/sbin/installer -verbose -pkg "${CBC_INSTALLER}" -target / 2>&1)
  err=${?}
  echo "${run_install_log}" >> "${LOG}"

  if [[ ${err} -eq 0 ]] ; then
    echo "Carbon Black Cloud sensor installed/upgraded successfully"
    exit 0
  else
    echo "Carbon Black Cloud sensor installation/upgrade error: ${err}"
    echo "${run_install_log}"

    # expose the pre/post install logs to console
    echo
    for pre_log in "${CBC_INSTALL_LOGS_PREFIX}"-preinstall-*.log ; do
      last_pre_log=${pre_log}
    done
    if [ -f "${last_pre_log}" ] ; then
      echo "${last_pre_log}:"
      cat "${last_pre_log}"
    fi

    echo
    for post_log in "${CBC_INSTALL_LOGS_PREFIX}"-postinstall-*.log ; do
      last_post_log=${post_log}
    done
    if [ -f "${last_post_log}" ] ; then
      echo "${last_post_log}:"
      cat "${last_post_log}"
    fi

    exit 10
  fi


}


function main() {

  init
  validate_options
  validate_run
  setup
  install
}


# run everything
main 2>&1 | tee -a "${LOG}"
