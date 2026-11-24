# Veil

A self-hosted store for passwords, tokens, and configuration, encrypted on the client and
delivered to processes, files, agents, and Bitwarden clients. One owner, many machines.

## Language

**Account**:
The unit one owner controls, served by one `veild` instance.
_Avoid_: tenant, instance, deployment, workspace

**Owner**:
The human who controls an Account and is the only principal allowed to write.
_Avoid_: user, admin, account holder

**Device**:
A machine the Owner has approved to read a Vault without further interaction.
_Avoid_: client, agent, node, host

**Workload**:
A short-lived principal authenticated by an external OIDC issuer, used by CI jobs.
_Avoid_: service account, machine account, integration, token

**Principal**:
A Device or a Workload. Principals read; only the Owner writes, including through a Bitwarden
client.
_Avoid_: grantee, identity, subject

**Vault**:
The unit of encryption and authorization: a named set of Items with one key and one approval
policy.
_Avoid_: environment, project, folder, collection

**Item**:
One sealed record in a Vault, in the Bitwarden SDK schema: login, secure note, card, identity,
or SSH key, with notes and custom fields.
_Avoid_: variable, secret, entry, cipher

**Field**:
One named value inside an Item: `username`, `password`, `notes`, `uri`, or a custom field.
_Avoid_: attribute, property, key

**Grant**:
What lets one Principal decrypt one Vault's key.
_Avoid_: permission, role, access, share

**Sealed record**:
A field the server stores but cannot read.
_Avoid_: ciphertext blob, encrypted value, envelope

**Reference**:
A `veil://vault/item/field` pointer, resolved on the client.
_Avoid_: URI, secret reference, path

**Revision**:
The monotonically increasing counter of a Vault, used to detect concurrent writes.
_Avoid_: version, generation, etag

**Change feed**:
The per-Vault list of Item IDs and revisions changed since a cursor, which clients sync from.
_Avoid_: sync document, bundle, payload, dump

**Session**:
An Owner's authenticated, expiring access to an Account. A Bitwarden login is a Session that
sees one Vault.
_Avoid_: login, token, auth

**Delivery**:
One act of putting a value into a process, a file, or a request.
_Avoid_: injection, export, fetch, read

**Approval policy**:
A Vault setting: `none`, `presence` (Touch ID per delivery), or `device` (approval on another
Device per delivery).
_Avoid_: confirm environment, protected, sensitive

## Relationships

- An Account has exactly one Owner, and any number of Vaults, Devices, Workloads, and
  Sessions.
- A Vault contains Items; an Item contains Fields.
- A Grant binds one Principal to one Vault.
- Every Vault name and every Item is a Sealed record; the server addresses them by ID.
- A Reference names a Field, never a Grant; resolving one requires a Grant for its Vault.
