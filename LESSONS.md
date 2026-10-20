# Lessons

What attacking and fixing two vulnerable LLM chatbots taught. The numbers are in the [README](README.md) and the
[case study](docs/case-study.md).

## As it turns out, all the fixes were classic web security

None of the fixes needed anything AI-specific. Each AI vulnerability gave way to a security fundamental:

| AI vulnerability | Fundamental that fixed it |
|---|---|
| Secret in the system prompt | **Secrets management:** keep secrets out of anything the model can see. It can't leak what it never had. |
| Model text triggers refunds | **Authentication and authorization:** identity from a server session, not the chat; a policy check on ownership, amount and return window; a signed, single-use, expiring token that only the customer's click redeems; fail closed on anything unknown. |
| Model output runs as script | **Output encoding and CSP:** render as text, plus a Content-Security-Policy with a per-request nonce. |
| No record of who did what | **Audit logging:** one line per decision with a request id, never the secret or the token. |

Two design principles carried the whole app: **deterministic controls**, and **treating every LLM response as
untrusted**. The model can propose; code decides. None of the fixes depended on the model behaving well, and they
held when the model was swapped.

## The model's safety training is an accidental guard, not a control

The model refused most obvious attacks: it wouldn't "repeat" XSS payloads (only 5% ran) and refused direct refund
requests. Simple reframing beat it every time. It wrote an `onerror` handler itself when asked for a helpful image
fallback, dumped its whole prompt when asked for "everything above", and refunded another customer's order when
the client forged a "Shall I proceed?" turn. One refusal even leaked the secret: *"I cannot write a poem spelling out
the code…"* Refusals are probabilistic, easy to reframe, and change with every model update.

## The canary caught what overlap missed, and the reverse

A random marker in the system prompt means any reply containing it is a prompt dump. It ran alongside a check for
the secret in disguise (spaced out, reversed, base64, leetspeak, acrostic) and a check for word-for-word prompt
overlap. A French translation of the prompt had no word overlap but kept the canary. A reworded bullet list dropped
the canary but overlapped. Each check caught attacks the others missed.

## The test harness made the results reproducible

An LLM gives a different answer each time, so "it worked once" proves nothing: one prompt leaked on the first try,
then 0 times in the next 10. The model's replies still vary; the harness makes the measurement repeatable: saved
prompt sets from public attack corpora, every prompt replayed several times, success decided by code (and by a real
browser for XSS), and a rate with a confidence interval. 0 out of 60 still means "up to about 6%", not "0%".

## LLM-written fixes need an LLM judge

Every patch the local model proposed was wrong as written: one returned the system prompt to every new user, one
approved the exact refund attack (the other customer's order exists and $899 is its price), and one called a
JavaScript library from Python. A second model reviewed each against a rubric (root cause, bypass, breaks normal
use, runs?), and each contributed one good idea. A generated fix is a starting point that needs review, tests and a
re-run of the original attack.

## A classifier's recall is not its value

A prompt-injection classifier flagged 80% of attack prompts with no false blocks, and still missed exactly the
attacks that worked: the forged-history refund (it only sees "Go ahead."), the image-fallback XSS, and an innocent
"what discount codes are available?" that leaked every time. Successful attacks look benign. On top of the
deterministic fixes it changed nothing. It belongs as tighten-only extra signal.

## Smaller lessons

- **A prompt dump is also an action injection.** The dumped prompt contains the action templates, and a naive app
  executes them. Scan for leaks before parsing actions.
- **Validation is not authorization.** "The order exists and the amount is under its price" approves another
  customer's refund. The missing input is *who is asking*.
- **Loosening the prompt can be safe once authority lives in code.** Telling the model its commands are only
  proposals made legitimate refunds work (0/3 → 3/3) while attacks stayed at 0.
- **Green health checks can hide a broken app.** A health check that lists models doesn't prove one can answer.
- **Keep security events durable.** A request id only helps if the log line it points to survived the restart.
