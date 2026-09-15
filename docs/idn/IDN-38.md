# IDN-38 — Release notes, signed and delivered with the release (§3, §8, §9)

**Priority:** P2 — hardening and reach

idunn delivers the update and the sidecars show it, so the question "what changes?"
belongs to the same path. Today a host has to fetch notes from somewhere else, with
nothing tying them to the release a user is asked to install.

Wanted, as data and never as code (AGENTS.md §1.3):

- **Delivered as TUF targets, discovered by name**, the way patches are (§3 of
  `packer.md`): `notes/v<major>/<version>/index.json` plus one file per language,
  `notes/v<major>/<version>/<lang>.md`. The index lists the languages and an optional
  link; the signed metadata answers whether notes exist at all. **The descriptor is not
  touched:** `release.ParseDescriptor` refuses unknown fields, so a `notes` field would
  make every deployed client refuse every new release. A client that knows nothing
  about notes never asks for the path. The release-line delegation takes the pattern
  `notes/v<major>/*` next to `payloads/v<major>/*` — a re-sign of `targets`, disjoint
  like the others, no client migration.
- **Link, embedded text, or both.** A publisher who keeps notes on a website ships
  only the index with `url`; one who wants them offline and bound to the release ships
  the text. The URL is `https` only, without credentials, validated by the packer and
  again by the client, and handed to the sidecar as a value — core opens nothing.
- **Bounded and strict.** The index goes through a strict parser like the descriptor
  (schema version, no unknown fields, fuzzed); a language tag is validated (BCP 47
  subset) before it becomes part of a path; the text has a size ceiling checked
  against the signed length before a byte is fetched.
- **Plain Markdown, rendered by the sidecar as untrusted text:** no raw HTML, no
  images or other remote content loaded automatically, links shown before they open.
  What the notes say is signed; what a renderer would do with active content is not.
- **API, called by the sidecar**, in line with IDN-36: something like
  `Updater.ReleaseNotes(ctx, rel, NotesOptions{Languages, Since})`, returning one entry
  per version with its language, text and link. `Since` is the installed version, so
  an update from 1.0 to 1.3 shows 1.1, 1.2 and 1.3 — the versions come from the signed
  targets metadata, as for multi-hop patches. The fallback order of languages is the
  caller's; with no match, the first language in the index. Notes are fetched on
  request, before `Apply`, and never required: a missing, oversized or malformed note
  is reported and does not block the update. Headless hosts never fetch them.
- **Packer:** `pack.yaml` takes `notes: { url: …, files: { en: CHANGELOG.md, de: … } }`;
  the notes are retired with their release (IDN-03).

Open: whether one release's notes may differ per platform (a `<os>-<arch>` override
next to the shared file) or stay one text per version; and whether `hook.Prompter`,
which today takes a plain question, grows a variant that carries the notes, or the
sidecar composes the question itself from the API.
