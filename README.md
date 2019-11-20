# Landing Zone early validation action

Performs an early validation on the LZ repository to fail as early as possible. 

## Inputs

### `REPO_PATH`

**Required** Location of the repository in your virtual environment. Default `"$GITHUB_WORKSPACE"`.

## Outputs

### `VALIDATION_RESULT`

The result of the validation.

## Example usage

```yaml
uses: actions/landing-zone-early-validation@master
with:
  REPO_PATH: "$GITHUB_WORKSPACE"
```
