---
title: Affected and fixed versions
summary: How "introduced", "fixed" and "last affected" describe the versions of a package that are vulnerable.
order: 110
keywords: version range, introduced, fixed, last_affected, affected versions, fixed version, semver, ecosystem, events, backport, release line
---

## What it is

Advisories describe affected versions as a list of **events**, read in order, in the OSV format:

| Event | Meaning |
|---|---|
| `introduced` | The first version that has the flaw (`0` means "from the very beginning") |
| `fixed` | The first version that no longer has it |
| `last_affected` | The last version with the flaw (used when no fix exists or the fix version is unknown) |

A range goes from an `introduced` to the next `fixed` (not included) or `last_affected` (included).

## Example

```
introduced 2.13.0  ->  fixed 2.15.0
```

- `2.12.4`: not affected (before the range)
- `2.13.0`, `2.14.1`: affected
- `2.15.0`, `2.17.1`: not affected (from the fix onward)

## Several ranges

A project often supports several **release lines** at once. The fix is then published for each one, giving several ranges:

```
introduced 2.0-beta9 -> fixed 2.3.1
introduced 2.4       -> fixed 2.12.2
introduced 2.13.0    -> fixed 2.15.0
```

In this case `2.12.1` is affected and the right fix is `2.12.2`, not `2.15.0`. Updating inside your line can be easier than jumping to a new major version.

## How the app shows them

The app repeats the ranges as text ("introduced 2.13.0 → fixed 2.15.0") and **does not decide** if your version is inside them. Maven
and npm sort versions with different rules (`1.0-beta` vs `1.0.0-beta`), so a general comparison would be wrong in some cases.

## Common mistakes

- **Reading `fixed` as inclusive.** The fixed version itself is safe.
- **Ignoring the line you are on.** Check for a `fixed` that matches your major and minor version.
- **Assuming the fix is complete.** A later advisory can show that the first fix was not enough.

## Keep investigating

- [OSV schema: affected ranges](https://ossf.github.io/osv-schema/)
- [Package advisories](/docs/concepts/package-advisories)
