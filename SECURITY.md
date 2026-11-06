# Security policy

## Supported versions

keyleash is pre-alpha and has no tagged release yet. Only the latest commit
on `master` receives fixes.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Report it privately
through GitHub's private vulnerability reporting ("Report a vulnerability"
on the repository's Security tab). If that button is not shown, open a
public issue that says only that you have a security report and asks for a
private contact; put no details of the vulnerability in it. Include in the
report:

- the version (`keyleash version`) and OS;
- what an attacker needs (same OS user? local admin? network access?) and
  what they gain;
- steps or a proof of concept, using test keys only.

Never include a real provider key, pass secret, passphrase or recovery code
in a report.

You can expect an acknowledgement within a week. Fixes are released on
`master` with a note in CHANGELOG.md; credit is given unless you ask
otherwise.

## Scope

The threat model, including what keyleash deliberately does not protect
against (for example malware running as your user while the vault is
unlocked, or administrator-level attackers), is in
[docs/SPEC.md §3](docs/SPEC.md#3-threat-model). Platform differences in
process confinement are in SPEC §12, "What is enforced where". Reports that
fall inside those stated limits are still welcome if they show a cheaper or
quieter attack than the documentation implies.
