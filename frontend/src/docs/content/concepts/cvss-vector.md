---
title: CVSS vector
summary: The short text string behind a CVSS score, and how to read it metric by metric.
order: 40
keywords: cvss vector, vector string, av, ac, pr, ui, scope, confidentiality, integrity, availability, attack vector, attack complexity, privileges required, user interaction, network, adjacent, local, physical, attack requirements
---

## What it is

A **vector** is the compact form of the answers that produce a [CVSS](/docs/concepts/cvss) score. It has a version at the start and
`metric:value` pairs separated by `/`:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

The score can be recalculated from the vector, and the vector is more useful than the number: it tells you **why** something is severe.

```diagram
cvss-vector
```

## The base metrics (CVSS 3.1)

| Metric | Question | Values |
|---|---|---|
| **AV** Attack Vector | From where can it be attacked? | **N**etwork (remotely, even over the Internet), **A**djacent (same network segment), **L**ocal (needs access to the machine), **P**hysical (touching the device) |
| **AC** Attack Complexity | Does it need special conditions? | **L**ow (works every time), **H**igh (depends on conditions the attacker does not control) |
| **PR** Privileges Required | Must the attacker be logged in? | **N**one, **L**ow (a basic user), **H**igh (admin) |
| **UI** User Interaction | Must a person do something? | **N**one, **R**equired (open a file, click a link) |
| **S** Scope | Does it break out of the vulnerable component? | **U**nchanged, **C**hanged (affects something beyond it, such as the host of a sandboxed app) |
| **C / I / A** | What is lost: confidentiality (data read), integrity (data changed), availability (service down)? | **H**igh (total), **L**ow (limited), **N**one |

Most worrying combination: `AV:N/AC:L/PR:N/UI:N`, meaning *remote, easy, no login, no user action*. That is what makes a flaw "wormable".

## Example

| Vector | Score | In words |
|---|---|---|
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 Critical | Log4Shell: remote, easy, no login, full impact, and it reaches beyond the vulnerable component |
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 Critical | Same, but the damage stays inside the vulnerable component |
| `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 5.5 Medium | Needs a local account; it can only read data |

## CVSS 4.0 vectors

They start with `CVSS:4.0/` and look like this:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

What changes:

- **AT** (Attack Requirements, `N` or `P`): conditions of the deployment that the attacker needs (such as a race condition). AC now covers only the
  defenses the attacker must evade.
- **UI** has three values: `N`one, `P`assive (limited interaction) and `A`ctive (a specific action).
- **Scope disappears.** The impact is given twice: **VC/VI/VA** for the vulnerable system and **SC/SI/SA** for the systems that come after.
- Optional groups after the base: **Threat** (`E`, exploit maturity: Attacked, Proof-of-concept, Unreported), **Environmental** and **Supplemental**
  (extra context that does not change the score).

## Common mistakes

- **Reading only the number.** Two 7.5 can be very different: one remote with no login, another that needs an admin.
- **Mixing versions.** `AV:N/AC:L/Au:N/C:P/I:P/A:P` (no `CVSS:` prefix) is CVSS v2; its letters mean different things.
- **Forgetting the context.** `PR:N` on a service that is only on your internal network is less urgent than on one exposed to the Internet.

## Keep investigating

- [CVSS 3.1 specification](https://www.first.org/cvss/v3-1/specification-document) and [4.0 specification](https://www.first.org/cvss/v4-0/specification-document)
- [FIRST's calculators](https://www.first.org/cvss/calculator/3-1) to try a vector yourself
