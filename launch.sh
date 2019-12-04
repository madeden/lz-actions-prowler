#!/bin/bash

DEBUG="true"

abort(){
  echo "$1"
  exit 1;
}

check_exec(){
  echo "Checking $1..."
  command -v "$1" >/dev/null 2>&1;
}

check_env(){
  echo "Checking environment"
  CHECK_EXECS="aws jq"
  for x in $CHECK_EXECS
  do  
    check_exec "$x" || abort "Unable to find $x"
  done
}

assume_role(){
  local STS_ROLE="$1"      
  local JSON_STS=""

  if [ -z "$STS_ROLE" ]; then
    abort "You must provide a role arn :("
  fi

  if [ "$DEBUG" == "true" ]; then
        aws sts get-caller-identity || abort "Unable to determine caller identity :("
  fi

  local unix_timestamp
  unix_timestamp=$(date +%s%N | cut -b1-13)

  JSON_STS=$(aws sts assume-role --role-arn "$STS_ROLE"  --role-session-name "session-$unix_timestamp")

  if [ -z "$JSON_STS" ]; then
    abort "Unable to assume role :("
  fi        

  unset AWS_ACCESS_KEY_ID
  unset AWS_SECRET_ACCESS_KEY
  unset AWS_SESSION_TOKEN

  export AWS_ACCESS_KEY_ID=$(echo "$JSON_STS" | jq -r .Credentials.AccessKeyId)
  export AWS_SECRET_ACCESS_KEY=$(echo "$JSON_STS" | jq -r .Credentials.SecretAccessKey)
  export AWS_SESSION_TOKEN=$(echo "$JSON_STS" | jq -r .Credentials.SessionToken)

  unset STS_ROLE
  unset JSON_STS
}

organizations_list_accounts(){
  local ACCOUNTS
  
  ACCOUNTS=$(aws organizations list-accounts)

  if [ -z "$ACCOUNTS" ]; then
    abort "Unable to list accounts :("
  fi

  echo "$ACCOUNTS"
  ACCOUNTS_IDS=$(echo "$ACCOUNTS" | jq -r .Accounts | jq -r ".[] | .Id")
}

check_input(){
  if [ -z "$1" ]; then
    abort "You must provide the IAM USER ID :("
  fi

  if [ -z "$2" ]; then
    abort "You must provide the IAM USER CREDENTIALS :("
  fi

  if [ -z "$3" ]; then
    abort "You must provide the AWSLandingZoneSecurityReadOnlyRole arn (From the security account)"
  fi

  if [ -z "$4" ]; then
    abort "You must provide the AWSLandingZoneReadOnlyListAccountsRole arn (From the primary account)"
  fi
}

#Validate input parameters
if [ "$#" -ne 4 ]; then
  abort "Invalid number of parameters :("
fi

PROWLER_USER_ID="$1"
PROWLER_ACCESS_KEY="$2"
PROWLER_READ_ROLE="$3"
PROWLER_LIST_ROLE="$4"

check_input "$PROWLER_USER_ID" "$PROWLER_ACCESS_KEY" "$PROWLER_READ_ROLE" "$PROWLER_LIST_ROLE"

#Set internal variables from the parameters (which are also environment variables)
export AWS_ACCESS_KEY_ID="$PROWLER_USER_ID"
export AWS_SECRET_ACCESS_KEY="$PROWLER_ACCESS_KEY"
export AWS_SESSION_TOKEN=""
FIRST_ROLE="$PROWLER_READ_ROLE"
SECOND_ROLE="$PROWLER_LIST_ROLE"

# List accounts retrieving the ID and store them in ACCOUNTS_ID variable
check_env
assume_role "$FIRST_ROLE"
assume_role "$SECOND_ROLE"
organizations_list_accounts

# Iterate over each ID launching prowler
for x in $ACCOUNTS_IDS
do
  echo "scanning account with id $x..."
  if [ "$x" == "473614850072" ]; then
    echo "Skipping account..."
  elif [ "$x" == "098920174900" ]; then
    echo "Skipping account..."
  else
    export AWS_ACCESS_KEY_ID="$PROWLER_USER_ID"
    export AWS_SECRET_ACCESS_KEY="$PROWLER_ACCESS_KEY"
    export AWS_SESSION_TOKEN=""
    
    assume_role "$FIRST_ROLE"
    assume_role "arn:aws:iam::$x:role/AWSLandingZoneReadOnlyExecutionRole"
    /prowler/prowler > "/tmp/prowler-$x" 2>&1 &
  fi
done

echo "Waiting for processes to end... results will be printed later, be patient, have a tea/coffee :)"
wait

# Print results
for x in $ACCOUNTS_IDS
do
  echo "Printing report for account: $x"
  echo "=========================================="
  cat "/tmp/prowler-$x"
done

echo "All good! bye!"
exit 0
