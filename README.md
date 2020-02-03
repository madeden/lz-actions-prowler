# Landing Zone Prowler action

Performs a prowler scan in parallel on every created account managed by the LZ printing the output for each account.

## Inputs

### `PROWLER_USER_ID`

**Required** The ID of the user.

### `PROWLER_ACCESS_KEY`

**Required** The IAM credentials for the user.

### `PROWLER_USER_ROLE`

**Required** ARN of the role AWSLandingZoneSecurityScannerRole in the security account.

### `PROWLER_ROLE`

**Required** ARN of the role AWSLandingZoneSecurityReadOnlyRole in the security account.

### `PROWLER_LIST_ROLE`

**Required** ARN of the role AWSLandingZoneReadOnlyListAccountsRole in the primary account.

## Example usage

```yaml
uses: madeden/lz-actions-prowler@master
with:
  PROWLER_USER_ID: ${{ secrets.PROWLER_USER_ID }}
  PROWLER_ACCESS_KEY: ${{ secrets.PROWLER_ACCESS_KEY }}
  PROWLER_USER_ROLE: ${{ secrets.PROWLER_USER_ROLE }}
  PROWLER_ROLE: ${{ secrets.PROWLER_ROLE }}
  PROWLER_LIST_ROLE: ${{ secrets.PROWLER_LIST_ROLE }}
```

The action uses the IAM credentials from an special user in the security account to assume the AWSLandingZoneProwlerScanRole in the security account. After that it uses the obtained credentials to assume the AWSLandingZoneReadOnlyListAccountsRole in the primary account, which in turns serves to retrieve the list of available accounts. 

Then using the IAM user credentials it assumes the AWSLandingZoneProwlerScanRole in the security account and then AWSLandingZoneReadOnlyExecutionRole in every existing account to launch in parallel prowler for each account.

## Required changes in the LZ for letting the action work

By default the landing zone doesn't provide the required infrastructure for making this action work. We decided to create an IAM user and allowed it to assume the different roles for listing accounts and performing the actual security scan. Some of the roles have to be created or modified, keep reading for more details.

### 1.- Creating a role in the primary account for listing accounts

The first step is creating the Role (The name of the role will be **AWSLandingZoneReadOnlyListAccountsRole** by default) that allows us to list the accounts, for doing it we created the following template file, and the following changes in the manifest file. Remember that the trick here is to remember that each template you created needs to be added to the manifest file. When the actual deployment is launched, templates in the manifest file will be processed in sequential order. Since the primary account is the last one in the manifest templates there will be processed at the end of the deployment process while templates in the security account are the first ones to be processed.

The Role policy states that it can be assumed by the SecurityAccountReadOnlyRole, so any user/Role with access to the SecurityAccountReadOnlyRole will be able to list the whole list of the accounts in our organization.

templates/core_accounts/aws-landing-zone-list-accounts-master.template:

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Configure the AWSLandingZoneReadOnlyListAccountsRole to enable listing all the accounts from the security account.

Parameters:
  SecurityAccountId:
    Type: String
    Description: Id of the Security account
  ReadOnlyListAccountsRoleName:
    Type: String
    Description: Role name for listing all the accounts.
    Default: AWSLandingZoneReadOnlyListAccountsRole

Resources:
  ReadOnlyListAccountsRole:
    Type: AWS::IAM::Role
    Metadata:
      cfn_nag:
        rules_to_suppress:
          - id: W28
            reason: "The role name is defined to allow cross account access from the security account."
          - id: W11
            reason: "The role needs access to all the organizations"
    Properties:
      Path: /
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/ReadOnlyAccess
      RoleName: !Ref ReadOnlyListAccountsRoleName
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              AWS:
                - !Sub arn:aws:iam::${SecurityAccountId}:root
            Action:
              - sts:AssumeRole
      Policies:
        - PolicyName: "AllowListingAccounts"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: "Allow"
                Action:
                  - "organizations:ListAccounts"
                Resource: "*"

Outputs:
  ReadOnlyListAccountsRole:
    Description: AWSLandingZoneReadOnlyListAccountsRole
    Value: !Ref ReadOnlyListAccountsRole

```

parameters/core_accounts/aws-landing-zone-list-accounts-master.json:

```json
[
  {
    "ParameterKey": "SecurityAccountId",
    "ParameterValue": "$[alfred_ssm_/org/member/security/account_id]"
  },
  {
    "ParameterKey": "ReadOnlyListAccountsRoleName",
    "ParameterValue": "AWSLandingZoneReadOnlyListAccountsRole"
  }
]


```

manifest.yaml:

```yaml
      - name: primary  # NOTE: DO NOT MODIFY THIS ACCOUNT NAME AND IT SHOULD BE THE LAST CORE ACCOUNT IN THE LIST
        ssm_parameters:
          # SSM parameter to hold the AWS Account ID of Organization's Master Account
          - name: /org/primary/account_id
            value: $[AccountId]
          # SSM parameter to hold the Email ID of Organization's Master Account
          - name: /org/primary/email_id
            value: $[AccountEmail]
          # SSM parameter to hold the Organization ID
          - name: /org/primary/organization_id
            value: $[OrganizationId]
        core_resources:
          - name: SecurityRolesListAccounts
            template_file: templates/core_accounts/aws-landing-zone-list-accounts-master.template
            parameter_file: parameters/core_accounts/aws-landing-zone-list-accounts-master.json
            deploy_method: stack_set
            ssm_parameters:
              - name: /org/primary/list_accounts_role_arn
                value: $[output_ReadOnlyListAccountsRole]
```

### 2 Allowing an IAM user in the security account to scan the other accounts

#### 2.1- Creating the IAM user, user policy and IAM role

In this second step we will create an IAM user inside the security account, it's associated user policy and IAM role. The user policy will allow the user to assume  **AWSLandingZoneProwlerScanRole**.

Assuming this role will allow us to actually run prowler against the different accounts. We will create IAM credentials for the user as well (For getting them we will have to look into the cloudformations output in the security account).

templates/core_accounts/aws-landing-zone-prowlerscan.template:

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Configure the AWS Landing Zone Security Roles to enable access to target accounts.

Parameters:
  SecurityScannerRoleName:
    Type: String
    Description: Name of the role allowed to run prowler.
    Default: AWSLandingZoneSecurityScannerRole

Resources:
  SecurityScannerRole:
    Type: AWS::IAM::Role
    Metadata:
      cfn_nag:
        rules_to_suppress:
          - id: W11
            reason: "Allow * in the ARN of the execution role to allow cross account access to user created child account in the AWS Organizations"
          - id: W28
            reason: "The role name is defined to identify AWS Landing Zone resources."
    Properties:
      RoleName: !Ref SecurityScannerRoleName
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              AWS:
                - !Sub arn:aws:iam::${AWS::AccountId}:root
            Action:
              - sts:AssumeRole
      Path: /
      Policies:
        - PolicyName: AssumeRole-AWSLandingZoneProwlerScanRole
          PolicyDocument:
            Version: 2012-10-17
            Statement:
              - Effect: Allow
                Action:
                  - sts:AssumeRole
                Resource:
                  - "arn:aws:iam::*:role/AWSLandingZoneReadOnlyExecutionRole"
                  - "arn:aws:iam::*:role/AWSLandingZoneReadOnlyListAccountsRole"

  SecurityScannerGroup:
    Type: AWS::IAM::Group
    DependsOn: SecurityScannerRole
    Properties:
      GroupName: SecurityScannerUsers
      Policies:
        - PolicyName: SecurityScannerPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - sts:AssumeRole
                Resource:
                  - !GetAtt SecurityScannerRole.Arn

  SecurityScannerUser:
    Type: AWS::IAM::User
    Properties:
      UserName: SecurityScannerUser
      Groups:
        - !Ref SecurityScannerGroup

  SecurityScannerUserAccessKey:
    Type: AWS::IAM::AccessKey
    DependsOn: SecurityScannerUser
    Properties:
      UserName: "SecurityScannerUser"

Outputs:
  CrossAccountSecurityScannerRoleName:
    Description: AWS Landing Zone Prowler Scan Configuration Role
    Value: !Ref SecurityScannerRole
  SecurityScannerUserAccessKeyID:
    Description: Prowler Scan Config User IAM User ID
    Value: !Ref SecurityScannerUserAccessKey
  SecurityScannerUserSecretAccessKey:
    Description: The actual Key associated with the IAM Prowler Scan Config User
    Value: !GetAtt 'SecurityScannerUserAccessKey.SecretAccessKey'

```

and the changes in the manifest file:

```yaml
      ...
      - name: security
        email: blah+security@blah.com
        ssm_parameters:
          - name: /org/member/security/account_id
            value: $[AccountId]
        core_resources:
          - ...
          - name: SecurityScannerMaster
            template_file: templates/core_accounts/aws-landing-zone-security-scanner.template
            parameter_file: parameters/core_accounts/aws-landing-zone-security-scanner.json
            deploy_method: stack_set
            ssm_parameters:
              - name: /org/member/security/security_scanner_role_name
                value: $[output_CrossAccountSecurityScannerRoleName]
          ...
```
Now that everything is in place, the action can be used against your LZ.
