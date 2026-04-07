# secret-lite

## Goal

**secret-lite** is a GitHub Action that automatically scans pull request diffs to detect accidentally committed secrets such as credentials, API keys, tokens, and other sensitive data.

By running as part of your CI pipeline, it intercepts secrets before they are merged into the main branch, reducing the risk of sensitive information being exposed in your repository history.

## Features

- Analyzes PR diffs for common secret patterns (API keys, credentials, tokens, etc.)
- Posts inline comments on the PR highlighting the detected violations
- Returns a structured JSON array of violations for further processing

## Usage

```yaml
- name: Secret Lite
  uses: mitigation-dot-team/secret-lite@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `github-token` | GitHub token with permissions to read PR diffs and post comments | Yes | `${{ github.token }}` |

## Outputs

| Output | Description |
|--------|-------------|
| `violations` | JSON array of detected secret violations |