---
layout: default
title: Admin Console Guide
---

# Admin Console Guide

This document holds the explanatory material that should not live inside the admin UI.

## Access Model

EndoriumFort now follows a three-layer access model:

1. `Role`
   Global capabilities such as user management, audit visibility, or session operations.
2. `Access Scope`
   The resources assigned to a given user.
3. `Resource Policy`
   Guardrails defined on the resource itself, such as:
   - justification required
   - dual approval
   - command guard
   - adaptive risk controls

The admin UI focuses on actions and state. This page is the place for the conceptual explanation.

## Admin MFA Rules

- Seeded `admin` accounts must rotate their initial password.
- MFA is mandatory for every admin account.
- Admins must keep at least one MFA factor active.
- MFA can be satisfied with:
  - TOTP
  - WebAuthn passkeys / security keys

## Relay Operations

`Relay Fabric` in the admin UI is intentionally action-focused.

Operational notes:

- Relay enrollment stays disabled unless `ENDORIUMFORT_RELAY_ENROLL_SECRET` is configured.
- Certificates and short-lived enrollment tokens can be generated from the admin console.
- Resource routing can stay direct or be bound to a relay.
- Online-only relay assignment is available to avoid routing toward stale relays.

## Resource Administration

Resource editing is split into these operational sections:

- `Identity`
- `Connectivity`
- `Access Policy`
- `Routing`

The form intentionally avoids long explanatory text. Use this page when onboarding operators or admins.

## Runtime Configuration

Backend runtime variables are documented in:

- [README](../README.md)
- [.env.example](../.env.example)
- [.env.prod.example](../.env.prod.example)

These cover:

- backend port
- session TTL
- WebAuthn RP ID / origin
- relay enrollment and token TTLs
