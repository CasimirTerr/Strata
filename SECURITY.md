# Security policy

## Reporting a problem

If you find a way to hide an attack from Strata, crash it with a crafted log file, or get the web page to run code from a log, please report it privately through GitHub: **Security** tab, then **Report a vulnerability**. Please don't open a public issue for these.

I'll reply within a week and credit you in the changelog unless you'd rather I didn't.

## What's in scope

- Evasion: attacker activity covered by a rule that Strata doesn't report
- Parsing bugs that a malicious CloudTrail file could trigger
- Script injection in the web page through log content
- Problems with the IAM permissions in `deploy/terraform`

Detection ideas for attacks Strata doesn't cover yet are welcome as normal issues.

## How the web page handles your logs

The page at casimirterr.github.io/Strata runs entirely in your browser. Files you load are read with the File API and never uploaded. All log content is escaped before it's displayed.
