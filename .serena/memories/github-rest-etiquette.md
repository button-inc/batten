# GitHub REST etiquette — how our tasks must call the API

Read when: writing or changing any task that calls the GitHub API (`ci-wait`,
`land`, `gh-preflight`), or diagnosing a 403/429/abuse response. Access and
token/proxy mechanics are `mem:github-access`; this is how to _behave_ once the
call goes out.

Upstream: [Best practices for using the REST API][bp]. Where this file and that
page disagree, the page wins.

[bp]: https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api

## Conditional requests are the default, not an optimisation

Save the response's `etag` (or `last-modified`) and send it back as
`if-none-match` on the next request. An unchanged resource answers **304 Not
Modified** with no body, and **a 304 does not count against the primary rate
limit**. Measured in this repo: three consecutive conditional requests left
`X-RateLimit-Used` unchanged.

Two consequences we rely on:

- **It is what pays for a short interval.** `ci-wait` polls every 5s because the
  polls that find nothing are free. An unconditional poll has to stay slow to
  stay affordable, which just means the verdict arrives late.
- **A 304 has no body.** Re-parsing it yields an empty result set, which for a
  poll reads as "no checks yet" and silently restarts the wait. Keep the previous
  reading on 304; a test must cover this, because the failure only shows up as
  unexplained slowness.

Keep request parameters _identical_ between polls, and request only what you
need — both raise the 304 hit rate.

## Polling

Upstream prefers webhooks and treats polling as the fallback. **We invert that
deliberately for CI**: webhooks drop successes, so silence is never green, and
an event-only wait hangs until the VM is reaped (`mem:github-access`, workflow
contract). Our poll is conditional, on a fixed interval, which is the shape the
page asks for when you must poll.

Honour `x-poll-interval` as a floor whenever the response carries one.

## Rate limits, and what to do when you hit one

- `retry-after` present → wait that many seconds. Not "about", that many.
- `x-ratelimit-remaining: 0` → wait until `x-ratelimit-reset` (UTC epoch seconds).
- Neither header → wait at least **one minute** before retrying.
- Repeated secondary-limit failures → exponential backoff, and **fail after a
  bounded number of retries** rather than looping forever. This is the one place
  a retry cap belongs; it is not in tension with our unbounded CI poll, which is
  bounded by CI completing.

Secondary limits are about _shape_, not volume: make requests **serially**, never
concurrently, and queue if you have many. When making POST/PATCH/PUT/DELETE in
bulk, wait **at least one second between each**.

## Status codes to handle deliberately

| Code        | Meaning for us                                                                                                                    |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `301`       | permanent redirect — update the code to the `location` URL                                                                        |
| `302`/`307` | temporary — follow it, change nothing                                                                                             |
| `304`       | success, unchanged, free                                                                                                          |
| `404`       | check auth/authorization before retrying; a private resource reads as absent, so never conclude "does not exist" from a 404 alone |
| `4xx`/`5xx` | fix the interaction, do not retry blindly                                                                                         |

## URLs and pagination

Never hand-construct or predict a URL, and never hand-roll `?page=N`: follow the
`link` header. Use a stable sort so pages stay consistent while you walk them.
Authenticate every request — anonymous calls get the much smaller limit.
