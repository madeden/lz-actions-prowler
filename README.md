# Landing Zone Prowler action

Performs a prowler scan on every created account managed by the LZ.

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
