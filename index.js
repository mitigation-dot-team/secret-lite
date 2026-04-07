#!/usr/bin/env node
'use strict';

/**
 * index.js — GitHub Action entry point for secret-lite
 *
 * Fetches the pull request diff from the GitHub API, scans every added line
 * for known secret patterns, posts a warning comment when findings exist, and
 * sets the `violations` output with a JSON array of findings.
 *
 * Inputs (GitHub Actions):
 *   github-token  – token with pull-requests:write permission
 *
 * Outputs (GitHub Actions):
 *   violations    – JSON array of detected secret violations
 */

const fs = require('fs');
const https = require('https');

// ---------------------------------------------------------------------------
// Secret detection rules
// ---------------------------------------------------------------------------
const SECRET_RULES = [
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/,
    message: 'AWS access key pattern detected. Move this value to environment variables.',
  },
  {
    name: 'AWS Secret Key',
    pattern: /(?:aws_secret(?:_access)?_key)\s*[=:]\s*(?:"[A-Za-z0-9/+=]{40}"|'[A-Za-z0-9/+=]{40}'|[A-Za-z0-9/+=]{40})/i,
    message: 'AWS secret access key detected. Move this value to environment variables.',
  },
  {
    name: 'Stripe Live Key',
    pattern: /sk_live_[0-9a-zA-Z]{24,}/,
    message: 'Stripe live API key detected. Move this value to environment variables.',
  },
  {
    name: 'JWT Token',
    pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_+/=]*/,
    message: 'JWT token detected. Do not hardcode JWT tokens in source code.',
  },
  {
    name: 'Private Key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    message: 'Private key detected. Never commit private keys to source control.',
  },
  {
    name: 'GitHub Token',
    pattern: /gh[pousr]_[0-9a-zA-Z]{36}/,
    message: 'GitHub personal access token detected. Move this value to environment variables.',
  },
  {
    name: 'Generic API Key',
    pattern: /(?:api[_-]?key)\s*[=:]\s*["']?[A-Za-z0-9_\-]{16,}["']?/i,
    message: 'Potential API key detected. Move this value to environment variables.',
  },
  {
    name: 'Generic Token',
    pattern: /(?:access_token|auth_token)\s*[=:]\s*["']?[A-Za-z0-9_\-]{16,}["']?/i,
    message: 'Potential token detected. Move this value to environment variables.',
  },
  {
    name: 'Hardcoded Password',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*(?:"[^"]{8,}"|'[^']{8,}'|[A-Za-z0-9_\-!@#$%^&*]{8,})/i,
    message: 'Potential hardcoded password detected. Move this value to environment variables.',
  },
  {
    name: 'Hardcoded Secret',
    pattern: /(?:secret)\s*[=:]\s*(?:"[^"]{8,}"|'[^']{8,}'|[A-Za-z0-9_\-!@#$%^&*]{8,})/i,
    message: 'Potential hardcoded secret detected. Move this value to environment variables.',
  },
];

// ---------------------------------------------------------------------------
// Diff parser
// ---------------------------------------------------------------------------

/**
 * @typedef {{ file: string, line: number, rule: string, message: string }} Finding
 */

/**
 * Parses a unified diff and returns one Finding for every added line that
 * matches at least one secret rule.
 *
 * @param {string} diffContent
 * @returns {Finding[]}
 */
function scanDiff(diffContent) {
  const findings = [];
  const lines = diffContent.split('\n');

  let currentFile = null;
  let newLineNumber = 0;

  for (const line of lines) {
    const fileMatch = line.match(/^diff --git a\/.+ b\/(.+)$/);
    if (fileMatch) {
      currentFile = fileMatch[1];
      newLineNumber = 0;
      continue;
    }

    const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunkMatch) {
      newLineNumber = parseInt(hunkMatch[1], 10) - 1;
      continue;
    }

    if (line.startsWith('+') && !line.startsWith('+++')) {
      newLineNumber++;
      const content = line.slice(1);

      for (const rule of SECRET_RULES) {
        if (rule.pattern.test(content)) {
          findings.push({
            file: currentFile,
            line: newLineNumber,
            rule: rule.name,
            message: rule.message,
          });
          break;
        }
      }
    } else if (!line.startsWith('-')) {
      newLineNumber++;
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// GitHub API helpers
// ---------------------------------------------------------------------------

/**
 * Makes an HTTPS request and returns the response body as a string.
 *
 * @param {object} options  https.request options
 * @param {string} [body]   optional request body
 * @returns {Promise<{ status: number, body: string }>}
 */
function request(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

/**
 * Fetches the unified diff for a pull request.
 *
 * @param {string} repo      owner/name
 * @param {number} prNumber
 * @param {string} token
 * @returns {Promise<string>}
 */
async function fetchPRDiff(repo, prNumber, token) {
  const [owner, name] = repo.split('/');
  const res = await request({
    hostname: 'api.github.com',
    path: `/repos/${owner}/${name}/pulls/${prNumber}`,
    method: 'GET',
    headers: {
      Accept: 'application/vnd.github.v3.diff',
      Authorization: `Bearer ${token}`,
      'User-Agent': 'secret-lite-action',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });

  if (res.status !== 200) {
    throw new Error(`Failed to fetch PR diff (HTTP ${res.status}): ${res.body}`);
  }

  return res.body;
}

/**
 * Posts a comment to a pull request.
 *
 * @param {string} repo
 * @param {number} prNumber
 * @param {string} body
 * @param {string} token
 * @returns {Promise<void>}
 */
async function postComment(repo, prNumber, body, token) {
  const data = JSON.stringify({ body });
  const [owner, name] = repo.split('/');
  const res = await request(
    {
      hostname: 'api.github.com',
      path: `/repos/${owner}/${name}/issues/${prNumber}/comments`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        Authorization: `Bearer ${token}`,
        'User-Agent': 'secret-lite-action',
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    },
    data,
  );

  if (res.status < 200 || res.status >= 300) {
    throw new Error(`GitHub API error ${res.status}: ${res.body}`);
  }
}

// ---------------------------------------------------------------------------
// Comment builder
// ---------------------------------------------------------------------------

/**
 * @param {Finding[]} findings
 * @returns {string}
 */
function buildComment(findings) {
  const lines = ['## 🚨 Potential secrets detected\n'];
  lines.push(
    '> **secret-lite** found patterns that look like secrets in this pull request.',
    '> Review each finding below and move any real credentials to environment variables or a secrets manager.\n',
  );

  for (const f of findings) {
    lines.push(
      '---',
      `**File:** \`${f.file}\`  `,
      `**Line:** ${f.line}  `,
      `**Rule:** ${f.rule}\n`,
      `> ${f.message}\n`,
    );
  }

  lines.push('---');
  lines.push(
    '_This comment was generated automatically by the [secret-lite](https://github.com/mitigation-dot-team/secret-lite) scanner._',
  );

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Actions helpers
// ---------------------------------------------------------------------------

/**
 * Reads an action input value.
 * GitHub Actions sets inputs as INPUT_<UPPERCASE_NAME> env vars.
 *
 * @param {string} name
 * @returns {string}
 */
function getInput(name) {
  return (process.env[`INPUT_${name.toUpperCase().replace(/ /g, '_')}`] || '').trim();
}

/**
 * Sets an action output value via the GITHUB_OUTPUT file (modern method).
 *
 * @param {string} name
 * @param {string} value
 */
function setOutput(name, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    fs.appendFileSync(outputFile, `${name}=${value}\n`);
  } else {
    // Fallback for older runners
    process.stdout.write(`::set-output name=${name}::${value}\n`);
  }
}

/**
 * Writes an error message that GitHub Actions will surface in the UI.
 *
 * @param {string} message
 */
function setFailed(message) {
  process.stderr.write(`::error::${message}\n`);
  process.exitCode = 1;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  // --- Resolve inputs -------------------------------------------------------
  const token = getInput('github-token');
  if (!token) {
    setFailed('Input "github-token" is required but was not provided.');
    return;
  }

  const repo = process.env.GITHUB_REPOSITORY;
  if (!repo) {
    setFailed('GITHUB_REPOSITORY environment variable is not set.');
    return;
  }

  // Pull request number from the event payload
  let prNumber;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (eventPath && fs.existsSync(eventPath)) {
    try {
      const event = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
      prNumber = event.pull_request && event.pull_request.number;
    } catch {
      // ignore parse errors
    }
  }

  if (!prNumber) {
    setFailed('Could not resolve pull request number. Make sure this action runs on a pull_request event.');
    return;
  }

  // --- Fetch diff & scan ----------------------------------------------------
  let diff;
  try {
    diff = await fetchPRDiff(repo, prNumber, token);
  } catch (err) {
    setFailed(`Failed to fetch PR diff: ${err.message}`);
    return;
  }

  const findings = scanDiff(diff);

  // --- Set output -----------------------------------------------------------
  setOutput('violations', JSON.stringify(findings));

  if (findings.length === 0) {
    console.log('✅ No secrets detected in this PR.');
    return;
  }

  console.log(`⚠️  ${findings.length} potential secret(s) detected:`);
  for (const f of findings) {
    console.log(`  [${f.rule}] ${f.file}:${f.line} — ${f.message}`);
  }

  // --- Post PR comment ------------------------------------------------------
  const comment = buildComment(findings);
  try {
    await postComment(repo, prNumber, comment, token);
    console.log('✅ Comment posted to pull request.');
  } catch (err) {
    setFailed(`Failed to post comment: ${err.message}`);
  }
}

main().catch((err) => {
  setFailed(err.message);
});
