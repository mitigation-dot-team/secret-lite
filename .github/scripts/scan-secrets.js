#!/usr/bin/env node
'use strict';

/**
 * scan-secrets.js
 *
 * Parses a git diff file, scans every added line for known secret patterns,
 * and posts a single warning comment to the pull request when findings exist.
 *
 * Usage:
 *   node scan-secrets.js <diff-file>
 *
 * Required environment variables (set automatically by GitHub Actions):
 *   GITHUB_TOKEN  – token with pull-requests:write permission
 *   PR_NUMBER     – pull request number
 *   REPO          – repository in "owner/name" format
 */

const fs = require('fs');
const https = require('https');
const path = require('path');

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
    // Track current file from the diff --git header
    const fileMatch = line.match(/^diff --git a\/.+ b\/(.+)$/);
    if (fileMatch) {
      currentFile = fileMatch[1];
      newLineNumber = 0;
      continue;
    }

    // Parse hunk header: @@ -old_start[,old_count] +new_start[,new_count] @@
    const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunkMatch) {
      newLineNumber = parseInt(hunkMatch[1], 10) - 1;
      continue;
    }

    if (line.startsWith('+') && !line.startsWith('+++')) {
      newLineNumber++;
      const content = line.slice(1); // strip leading '+'

      for (const rule of SECRET_RULES) {
        if (rule.pattern.test(content)) {
          findings.push({
            file: currentFile,
            line: newLineNumber,
            rule: rule.name,
            message: rule.message,
          });
          break; // one finding per line is enough
        }
      }
    } else if (!line.startsWith('-')) {
      // Context line (unchanged) — advance the new-file line counter
      newLineNumber++;
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// GitHub API helpers
// ---------------------------------------------------------------------------

/**
 * Posts a comment to a pull request.
 *
 * @param {string} repo       owner/name
 * @param {number} prNumber
 * @param {string} body       comment body (Markdown)
 * @param {string} token      GITHUB_TOKEN
 * @returns {Promise<void>}
 */
function postComment(repo, prNumber, body, token) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ body });
    const [owner, name] = repo.split('/');
    const options = {
      hostname: 'api.github.com',
      path: `/repos/${owner}/${name}/issues/${prNumber}/comments`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        Authorization: `Bearer ${token}`,
        'User-Agent': 'secret-lite-scanner',
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2026-03-10',
      },
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve();
        } else {
          reject(new Error(`GitHub API error ${res.statusCode}: ${body}`));
        }
      });
    });

    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Comment builder
// ---------------------------------------------------------------------------

/**
 * Builds a Markdown comment body from a list of findings.
 *
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
// Main
// ---------------------------------------------------------------------------

async function main() {
  const diffFile = process.argv[2];
  if (!diffFile) {
    console.error('Usage: scan-secrets.js <diff-file>');
    process.exit(1);
  }

  if (!fs.existsSync(diffFile)) {
    console.error(`Diff file not found: ${diffFile}`);
    process.exit(1);
  }

  const token = process.env.GITHUB_TOKEN;
  const prNumber = process.env.PR_NUMBER;
  const repo = process.env.REPO;

  if (!token || !prNumber || !repo) {
    console.warn('GITHUB_TOKEN, PR_NUMBER or REPO not set — skipping comment.');
    process.exit(1);
  }

  const diffContent = fs.readFileSync(diffFile, 'utf8');
  const findings = scanDiff(diffContent);

  let comment;
  if (findings.length === 0) {
    console.log('✅ No secrets detected in this PR.');
    comment = '✅ No secrets detected in this pull request.';
  } else {
    console.log(`⚠️  ${findings.length} potential secret(s) detected:`);
    for (const f of findings) {
      console.log(`  [${f.rule}] ${f.file}:${f.line} — ${f.message}`);
    }
    comment = buildComment(findings);
  }

  try {
    await postComment(repo, parseInt(prNumber, 10), comment, token);
    console.log('✅ Comment posted to pull request.');
  } catch (err) {
    console.error('Failed to post comment:', err.message);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
