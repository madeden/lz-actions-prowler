# Landing Zone Prowler action

Performs a prowler scan in parallel on every created account managed by the LZ printing the output for each account.

## Inputs

### `PROWLER_USER_ID`

**Required** The ID of the user.

### `PROWLER_ACCESS_KEY`

**Required** The IAM credentials for the user.

### `PROWLER_READ_ROLE`

**Required** ARN of the role AWSLandingZoneSecurityReadOnlyRole in the security account.

### `PROWLER_LIST_ROLE`

**Required** ARN of the role AWSLandingZoneReadOnlyListAccountsRole in the primary account.

## Example usage

```yaml
uses: madeden/lz-actions-prowler@master
with:
  PROWLER_USER_ID: ${{ secrets.PROWLER_USER_ID }}
  PROWLER_ACCESS_KEY: ${{ secrets.PROWLER_ACCESS_KEY }}
  PROWLER_READ_ROLE: ${{ secrets.PROWLER_READ_ROLE }}
  PROWLER_LIST_ROLE: ${{ secrets.PROWLER_LIST_ROLE }}
```

The action uses the IAM credentials from a user in the security account to assume the AWSLandingZoneSecurityReadOnlyRole in the security account. After that it uses the obtained credentials to assume the AWSLandingZoneReadOnlyListAccountsRole, which in turns serves to retrieve the list of available accounts. 

Then using the IAM user credentials it assumes the AWSLandingZoneReadOnlyExecutionRole in every existing account to launch in parallel prowler for each account.

# Required changes in the LZ for letting the action work

By default the landing zone doesn't provide the required infrastructure for making this action work. We decided to create an IAM user and allowed it to assume the different roles for listing accounts and performing the actual security scan. Some of the roles have to be creted, keep reading for more details.

## 1.- Creating a role in the primary account for listing accounts
The first step is creating the Role (The name of the role will be **AWSLandingZoneReadOnlyListAccountsRole** by default) that allows us to list the accounts, for doing it we created the following template file, and the following changes in the manifest file. Remember that the trick here is to remember that each template you created needs to be added to the manifest file and when the actual deployment is launched, templates in the manifest file will be processed in sequential order, effectively making the primary account the last one to be processed.

The Role policy states that it can be assumed by the SecurityAccountReadOnlyRole, so any user/Role with access to the SecurityAccountReadOnlyRole will be able to list the whole list of the accounts in our organization.

templates/core_accounts/aws-landing-zone-list-accounts-master.template:
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Configure the AWSLandingZoneReadOnlyListAccountsRole to enable listing all the accounts from the security account.

Parameters:
  SecurityAccountReadOnlyRoleArn:
    Type: String
    Description: Admin role ARN from the security account. 
  ReadOnlyListAccountsRoleName:
    Type: String
    Description: Role name for listing all the accounts.
    Default: AWSLandingZoneReadOnlyListAccountsRole 
  EnableReadOnlyListAccountsRole:
    Type: String
    Default: 'true'
    Description: Create a read-only cross-account role from SecurityAccountId to this account.
    AllowedValues:
      - 'true'
      - 'false'

Conditions:
  CreateReadOnlyListAccountsRole: !Equals
    - !Ref EnableReadOnlyListAccountsRole
    - 'true'

Resources:
  ReadOnlyListAccountsRole:
    Type: AWS::IAM::Role
    Metadata:
      cfn_nag:
        rules_to_suppress:
          - id: W28 
            reason: "The role name is defined to allow cross account access from the security account."
    Condition: CreateReadOnlyListAccountsRole
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
                - !Ref SecurityAccountReadOnlyRoleArn
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
  MasterAccountId:
    Description: Master Account ID
    Value: !Sub '${ AWS::AccountId }'

```

parameters/core_accounts/aws-landing-zone-list-accounts-master.json:
```json
[
  {
      "ParameterKey": "SecurityAccountReadOnlyRoleArn",
      "ParameterValue": "$[alfred_ssm_/org/member/security/readonly_role_arn]"
  },        
  {
      "ParameterKey": "ReadOnlyListAccountsRoleName",
      "ParameterValue": "AWSLandingZoneReadOnlyListAccountsRole"
  },
  {
      "ParameterKey": "EnableReadOnlyListAccountsRole",
      "ParameterValue": "true"
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
              - name: /org/primary/master_account_id
                value: $[output_MasterAccountId]
```

## 2 Allowing an IAM user in the security account to scan the other accounts
### 2.1- Creating the IAM user and the user policy

In this second step we will create an IAM user inside the security account, and it's associated user policy. The user policy will allow the user to assume the **AWSLandingZoneReadOnlyExecutionRole** (This role is provided by the default LZ setup). Assuming this role will allow us to actually run prowler against the different accounts. We will create IAM credentials for the user as well (For getting them we will have to look into the cloudformations output in the security account).

templates/core_accounts/aws-landing-zone-security-scanner.template:
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Configure the SecurityScannerUser user for running prowler

Resources:
  SecurityScannerUser:
    Type: AWS::IAM::User
    Metadata:
      cfn_nag:
        rules_to_suppress:
          - id: F2000
            reason: "We are not going to use groups yet"
    Properties:
      UserName: SecurityScannerUser
  
  SecurityScannerUserAccessKey:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName: "SecurityScannerUser"
    DependsOn: SecurityScannerUser  

Outputs:
  SecurityScannerUserArn:
    Description: Security Scanner user arn to be used in other templates.
    Value: !GetAtt 'SecurityScannerUser.Arn'
  SecurityScannerAccessKeyID:
    Description: Security Scanner IAM User ID
    Value: !Ref SecurityScannerUserAccessKey
  SecurityScannerSecretAccessKey:
    Description: The actual Key associated with the IAM security scanner User
    Value: !GetAtt 'SecurityScannerUserAccessKey.SecretAccessKey'
```

templates/core_accounts/aws-landing-zone-security-scanner-policy.template
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Configure the SecurityScannerUser policy for running prowler

Resources:
  SecurityScannerUserPolicy:
    Type: AWS::IAM::Policy
    Metadata:
      cfn_nag:
        rules_to_suppress:
          - id: W12
            reason: "Allow * in the ARN of the execution role to allow cross account access to user created child account in the AWS Organizations"
          - id: F11
            reason: "Allow policy on user since it doesn't work on groups"
    Properties:
      PolicyName: "SecurityScannerUserPolicy"
      Users: 
        - SecurityScannerUser
      PolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Action:
              - sts:AssumeRole
            Resource:
              - "arn:aws:iam::*:role/AWSLandingZoneReadOnlyExecutionRole"
```

As you see there is a dependency between the Policy and the User, the user must be created first, this can be solved by listing the files in order in the manifest file, our security account section must look like the following snippet:

```yaml
      ...
      - name: security
        email: blah+security@blah.com
        ssm_parameters:
          - name: /org/member/security/account_id
            value: $[AccountId]
        core_resources:
          - name: SecurityScannerUser
            template_file: templates/core_accounts/aws-landing-zone-security-scanner.template
            deploy_method: stack_set
            ssm_parameters:
              - name: /org/member/security/scanner_user_arn
                value: $[output_SecurityScannerUserArn]
            # There might be other resources here
          - name: SecurityRoles
            template_file: templates/core_accounts/aws-landing-zone-security.template
            parameter_file: parameters/core_accounts/aws-landing-zone-security.json
            deploy_method: stack_set
            ssm_parameters:
              - name: /org/member/security/admin_role_arn
                value: $[output_CrossAccountAdminRole]
              - name: /org/member/security/readonly_role_arn
                value: $[output_CrossAccountReadOnlyRole]
          - name: SecurityScannerUserPolicy
            template_file: templates/core_accounts/aws-landing-zone-security-scanner-policy.template
            deploy_method: stack_set
          - name: SharedTopic
          ...    
```

### 2.2.- Modify the ReadOnlyExecutionRole

Now we have to modify the template aws_baseline/aws-landing-zone-security-roles.template file to allow our user to assume the role ReadOnlyExecutionRole. This role will be assumed for each account (The role is created repeteadly in each account by default) before launching prowler.

First we add our user ARN as a parameter:

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Configure the AWSLandingZoneAdminExecutionRole to enable read only access the target account.

Parameters:
  SecurityScannerUserArn:
    Type: String
    Description: ARN of the user allowed to run prowler.
  SecurityAccountAdminRoleArn:
    Type: String
    Description: Admin role ARN from the security account.
    ...
```

Then in the ReadOnlyExecutionRole IAM Role resource we state the principals in the following way so that our recently created IAM user has access to it:
```yaml
  ReadOnlyExecutionRole:
    Type: AWS::IAM::Role
    Metadata:
      cfn_nag:
        rules_to_suppress:
          - id: W28
            reason: "The role name is defined to allow cross account access from the security account."
    Condition: CreateReadOnlyRole
    Properties:
      RoleName: !Ref ReadOnlyRoleName
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              AWS:
                - !Ref SecurityAccountReadOnlyRoleArn
                - !Ref SecurityScannerUserArn
            Action:
              - sts:AssumeRole
      Path: /
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/ReadOnlyAccess
```

## 3.- Allowing role chainning

Now we move back to the SecurityAccountReadOnlyRole we used in the first step. This Role is defined in the following template file templates/core_accounts/aws-landing-zone-security.template . Role chainning has to be defined in both directions, we already stated that SecurityAccountReadOnlyRole can be used to assume the AWSLandingZoneReadOnlyListAccountsRole now we have to specify the other direction, we have to modify the template:

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Configure the AWS Landing Zone Security Roles to enable access to target accounts.

Parameters:
  SecurityScannerUserArn:
    Type: String
    Description: ARN of the user allowed to run prowler.
  AdminRoleName:
    Type: String
    Description: Role name for administrator access.
    Default: AWSLandingZoneSecurityAdministratorRole
  ReadOnlyRoleName:
    Type: String
    Description: Role name for read-only access.
    Default: AWSLandingZoneSecurityReadOnlyRole  
...
...
  ReadOnlyRole:
    Type: AWS::IAM::Role
    Metadata:
      cfn_nag:
        rules_to_suppress:
          - id: W11
            reason: "Allow * in the ARN of the execution role to allow cross account access to user created child account in the AWS Organizations"
          - id: W28
            reason: "The role name is defined to identify AWS Landing Zone resources."
    Properties:
      RoleName: AWSLandingZoneSecurityReadOnlyRole
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudformation.amazonaws.com
              AWS:
                - !Ref SecurityScannerUserArn
            Action:
              - sts:AssumeRole
      Path: /
      Policies:
        - PolicyName: AssumeRole-AWSLandingZoneSecurityReadOnlyRole
          PolicyDocument:
            Version: 2012-10-17
            Statement:
              - Effect: Allow
                Action:
                  - sts:AssumeRole
                Resource:
                  - "arn:aws:iam::*:role/AWSLandingZoneReadOnlyExecutionRole"
                  - "arn:aws:iam::*:role/AWSLandingZoneReadOnlyListAccountsRole"
                 
Outputs:
  CrossAccountAdminRole:
    Description: AWS Landing Zone Security Administrator Role
    Value: !GetAtt 'AdministrationRole.Arn'
  CrossAccountReadOnlyRole:
    Description: AWS Landing Zone Security ReadOnly Role
    Value: !GetAtt 'ReadOnlyRole.Arn'                  
```

parameters/core_accounts/aws-landing-zone-security.json:
```json
[
  {
      "ParameterKey": "SecurityScannerUserArn",
      "ParameterValue": "$[alfred_ssm_/org/member/security/scanner_user_arn]"
  },
  {
    "ParameterKey": "AdminRoleName",
    "ParameterValue": "AWSLandingZoneSecurityAdministratorRole"
  },
  {
    "ParameterKey": "ReadOnlyRoleName",
    "ParameterValue": "AWSLandingZoneSecurityReadOnlyRole"
  }
]

```

Now that everything is in place, the action can be used against your LZ.