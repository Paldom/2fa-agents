# Driving a 2FA challenge: recipes per tool

**Contents:** [Session reuse (do this first)](#session-reuse-do-this-first) ·
[Playwright TypeScript](#playwright-typescript) · [Playwright Python](#playwright-python) ·
[Agentic browser tools](#agentic-browser-tools) · [Selenium](#selenium) ·
[CLI logins](#cli-logins) · [Finding the 2FA field](#finding-the-2fa-field) ·
[CI checklist](#ci-checklist) · [Sources](#sources)

Every recipe assumes a **code command** that prints one code to stdout and exits 0.
`CODE_COMMAND` below stands for whichever one applies.

## Session reuse (do this first)

Authenticating once and reusing the state removes the 2FA step from every run but
one. It is the difference between one challenge per day and one per test.

Decision order:

1. Valid saved session → use it, no login at all.
2. A login **API** exists → authenticate over HTTP, save cookies, no browser.
3. Otherwise → UI login with 2FA once, in setup, and save the state.
4. Keep exactly one test that does the real 2FA path, so a broken flow is still caught.

The saved state is a live credential. Gitignore it (`playwright/.auth/`), give it
mode 600, and expect it to expire — validate before use and re-authenticate on
failure rather than letting a stale file produce confusing downstream errors.

## Playwright TypeScript

```ts
// auth.setup.ts — runs once as a dependency of the other projects
import { test as setup, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';

const AUTH = 'playwright/.auth/user.json';
const code = () => execFileSync('python3',
  [process.env.TOTP_SCRIPT!, '--file', process.env.TOTP_SECRET_FILE!, '--min-validity', '5'],
  { encoding: 'utf8' }).trim();

setup('authenticate', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('Email').fill(process.env.LOGIN_USER!);
  await page.getByLabel('Password').fill(process.env.LOGIN_PASS!);
  await page.getByRole('button', { name: /sign in/i }).click();

  const field = page.getByLabel(/authentication code|one-time|verification code/i);
  await expect(field).toBeVisible({ timeout: 15_000 });

  // Generate LAST. --min-validity 5 blocks until a window with >=5s remains.
  await field.fill(code());
  await page.getByRole('button', { name: /verify|continue|submit/i }).click();

  await page.waitForURL(/\/dashboard/);          // wait for the outcome, not a sleep
  await page.context().storageState({ path: AUTH });
});
```

```ts
// playwright.config.ts
projects: [
  { name: 'setup', testMatch: /auth\.setup\.ts/ },
  { name: 'chromium', dependencies: ['setup'],
    use: { storageState: 'playwright/.auth/user.json' } },
]
```

Use `execFileSync` with an argument array rather than `execSync` with an interpolated
string: no shell means no quoting bug and no injection from an environment value.

## Playwright Python

```python
import subprocess
from playwright.sync_api import sync_playwright, expect

def code() -> str:
    return subprocess.run(["python3", TOTP, "--file", SECRET, "--min-validity", "5"],
                          capture_output=True, text=True, check=True).stdout.strip()

with sync_playwright() as p:
    context = p.chromium.launch().new_context()
    page = context.new_page()
    page.goto(f"{BASE}/login")
    page.get_by_label("Email").fill(USER)
    page.get_by_label("Password").fill(PASSWORD)
    page.get_by_role("button", name="Sign in").click()

    field = page.get_by_label(re.compile("authentication code|one-time", re.I))
    expect(field).to_be_visible(timeout=15_000)
    field.fill(code())
    page.get_by_role("button", name=re.compile("verify|continue", re.I)).click()
    page.wait_for_url(re.compile(r"/dashboard"))
    context.storage_state(path="playwright/.auth/user.json")
```

## Agentic browser tools

Driving a real browser through an agent tool (Claude in Chrome, Playwright MCP,
computer-use loops) changes the timing, not the rules:

- Run the code command in the **same turn** as the fill and submit. A code fetched
  one turn earlier is usually dead — model turns take seconds.
- Never paste the code into a chat message on the way to the form; it lands in the
  transcript, which is logged and cached.
- Read the page after submitting and branch on the actual result. Do not assume
  success; do not re-click submit.
- If the page shows a push/WebAuthn prompt, stop. Retrying a fill against it does
  nothing except consume the session.

## Selenium

```python
WebDriverWait(driver, 15).until(
    EC.visibility_of_element_located((By.CSS_SELECTOR, "input[autocomplete='one-time-code']"))
).send_keys(code())
```

Selenium has no `storageState` equivalent: reuse a persistent browser profile
directory, or extract cookies with `driver.get_cookies()` and re-add them with
`driver.add_cookie()` after navigating to the domain first.

## CLI logins

Many CLIs accept the code as a flag or read it from stdin — always prefer that to an
`expect` script:

```bash
npm publish --otp "$(op item get npmjs --otp)"
gh auth login --with-token < token.txt         # no TOTP needed; tokens beat scripted 2FA
aws sts get-session-token --serial-number "$MFA_ARN" --token-code "$(CODE_COMMAND)"
```

Where the CLI supports a **long-lived token or an API key**, use that instead of
automating a 2FA login at all. It is revocable, scoped, and does not expire in 30
seconds.

If a prompt is unavoidable, `expect` is the last resort — and the code must be
generated inside the expect block, not before it.

## Finding the 2FA field

Ordered by robustness:

1. `input[autocomplete="one-time-code"]` — the standard attribute, widely used.
2. Accessible label/placeholder regex: `/authentication code|one-time|verification|2fa|otp/i`.
3. `input[inputmode="numeric"]` with `maxlength` 6–8.
4. Brittle CSS/XPath — last resort, breaks on every redesign.

Watch for: the field being in an **iframe** (`page.frameLocator(...)`), split
six-box inputs (fill each, or `fill()` the first — many implementations spread the
paste), and the challenge living on a separate URL after the password step.

## CI checklist

- [ ] Runner clock is NTP-synced (drift > ~±30 s breaks every code).
- [ ] Seed comes from the CI secret store, never the repo.
- [ ] Code is generated immediately before submit, with `--min-validity`.
- [ ] One authentication per run, shared via session state — not one per test.
- [ ] Parallel workers do not each log into the same account.
- [ ] Attempt cap of two, no retry loop.
- [ ] No code, seed or password echoed into build logs or artifacts.
- [ ] Auth-state artifacts are not uploaded or cached between jobs.

## Sources

- Playwright authentication — <https://playwright.dev/docs/auth>
- `autocomplete="one-time-code"` — <https://developer.mozilla.org/docs/Web/HTML/Attributes/autocomplete>
- RFC 6238 §5.2 (single use per time step, validation window) — <https://www.rfc-editor.org/rfc/rfc6238>
