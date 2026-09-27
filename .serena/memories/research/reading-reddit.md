# Reading a Reddit thread from a remote container

reddit.com blocks this container on every host (www, old, api, `.json`): the response is a block page, not the thread. Read it through the arctic-shift archive instead:

- the post: `https://arctic-shift.photon-reddit.com/api/posts/ids?ids=<id>`
- the comments: `https://arctic-shift.photon-reddit.com/api/comments/tree?link_id=<id>&limit=9999`

`<id>` is the base36 segment after `/comments/` in the thread URL. Flatten both into markdown in the scratchpad before reading.

**A link the operator supplies is read in full.** If it cannot be read, the failure and the link go on the board. It is never dismissed with a verdict formed without reading it (measured 2026-09-27: CLOUD-1945 was first written from compio's own docs while the owner's thread was left unread).
