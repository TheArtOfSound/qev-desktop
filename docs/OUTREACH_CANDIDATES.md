# Outreach Candidates — `/chat` Browser Envelope

**Audience:** Bryan only. This file is a working draft, not a public doc.
**Status:** Pre-launch. Zero outreach has been sent as of writing.
**Updated:** 2026-04-15

## Why this file exists

The `/chat` browser envelope is the sharpest shippable wedge in
BRY-NFET-SX right now. The single biggest missing piece for it is not
more code — it is ten conversations with people who already hate the
current way of sharing one-off secrets.

This file lists ten *types* of person where that pain is concrete and
recurring, plus a short outreach email template. The purpose is to
force clarity about **who to actually email**, not to generalize more.

Rules for this list:

- Each entry must name a specific role and a specific pain moment,
  not an abstract category like "security teams."
- Each entry must be someone whose workflow currently involves
  sharing a one-off secret across a channel they don't fully trust.
- If the person doesn't already feel friction today, they will not
  become a user tomorrow. Cold cases are weaker than warm frustration.

## The frozen pitch (one sentence)

> `/chat` is a browser-only encrypted envelope for one-off secret
> sharing. Zero network requests after page load, verifiable in
> DevTools. No account. No server. Send the file through one channel
> and the phrase through another.

That is the entire pitch. Do not expand it. Do not mix it with the
envelope platform. Do not mix it with NFET. The platform and NFET
exist to make `/chat` *credible*, not to be pitched alongside it.

## Ten candidate personas

Each persona describes a real pain moment. Find a specific person who
fits each one — not a hypothetical. If you can't name someone specific
by the end of the week, the real blocker isn't the product, it's the
distribution path.

### 1. Security engineer at a 20-100 person B2B SaaS, during offboarding

The painful moment: an engineer leaves. Ops needs to hand the
replacement a production secret or a vendor token, *once*. Slack is
audited and permanent. Email is trivially leaked. 1Password requires
onboarding a new account and paying for a seat for a single handoff.
The current workaround is usually "type it into a private DM and
delete the message" — which doesn't delete it, and both sides know it.

### 2. Incident responder handing a triage credential to a contractor

The painful moment: a vendor is brought in during an incident. They
need one credential to read one system. Creating them a SSO account
takes hours they don't have, and the credential will be revoked in
24-48 hours anyway. Today they paste it into a bridge chat or a
Zoom private message.

### 3. Compliance officer sending a sensitive document access phrase
   to an auditor

The painful moment: an external auditor needs a one-time passphrase
for a data room. The passphrase is already generated. It needs to go
to the auditor and nowhere else. Email puts a copy on Microsoft's
servers forever. Phoning it in loses the paper trail. The current
solution is usually "email half in one message, half in a follow-up"
— which is security theater.

### 4. HR manager sending a new hire's starter credentials

The painful moment: day-one credentials. Corporate email works
eventually but not yet. Personal email has the wrong trust boundary.
The hire is not yet on the internal chat system. Today this is often
"text it to them and trust the phone."

### 5. Doctor sending patient-relevant info to a family member
   (non-HIPAA-sensitive, just private)

The painful moment: "Tell your sister the medication name, but
don't put it in an email because the in-laws share the account."
Signal works if both sides have it. SMS doesn't. Email is wrong.
Paper is the current answer.

### 6. Lawyer sending a settlement password to a client

The painful moment: the client is non-technical and uses Gmail for
everything. The lawyer is forbidden by policy from sending sensitive
client communications through regular email. The firm's "secure
portal" product requires the client to create an account, which
the client will never actually do. Today this is solved by phone
call and typed PDFs.

### 7. DevOps lead rotating a service account password once a quarter

The painful moment: a shared service credential needs to land in a
CI/CD system and nowhere else. The current workflow involves a
vault rotation tool, an ops handoff, and three humans who briefly
see the cleartext. Most of the attack surface is the "briefly see"
part. A one-shot envelope that a single human types in and a single
human decrypts reduces the window.

### 8. Product security person sharing a reproduction step for a bug
    that includes a live token

The painful moment: you found a vulnerability. You need to send it
to a vendor. The PoC requires a token that still works. Email is
wrong. Signal is wrong (no paper trail). The vendor's "secure
disclosure" form usually times out. Today you PGP-encrypt and half
the time the vendor can't decrypt.

### 9. Whistleblower / source intake at a journalism outlet

The painful moment: a source wants to send one document. SecureDrop
is heavy and scary. Signal is lightweight but requires account
metadata. ProtonMail is an account. A browser-only envelope with
zero network dependency is the right shape *for the source*, even
if the journalist then copies out to something more robust for
retention.

### 10. Non-technical family member sharing a password with an
     elderly parent on a phone call

The painful moment: mom needs the new wifi password. She is not
going to install Signal. She is not going to sign up for LastPass.
She needs to open a tab, type a phrase her adult child reads to her
on the phone, and see the wifi password. This is the "grandma" case
Bryan has already called out internally — but it is also real, it
happens at least once in every family per year, and it is the case
that validates the no-install constraint.

## Email template

Use this as a starting point. Customize per recipient. Do not
cold-blast.

---

Subject: `A 5-minute idea for [specific pain] — feedback would mean a lot`

Hi [Name],

I'm Bryan. I'm building a small tool and I'd like your honest read
on whether it solves a real problem for you.

The pain I'm trying to solve: you sometimes need to send one secret
to one person, once. Every current option is either too heavy (new
account, new app) or too leaky (email, chat, text). I saw [specific
moment — e.g. "your recent post about offboarding handoffs", or
"the conversation we had at $event about rotating vendor tokens"]
and thought this might ring a bell.

My approach: a single web page. You type a message and a phrase.
The page gives you an encrypted file. You send the file through
one channel and tell the other person the phrase through another.
No account, no server — open DevTools during the encrypt and you
can watch there are zero network requests. The code is open and
SRI-signed so you can verify the page you loaded is the one we
published.

It is live at https://secure.imagineqira.com/chat — no signup.

I am specifically looking for:

1. Does this fit a moment in your actual workflow?
2. If yes, what would make it obviously broken for that moment?
3. If no, what would I need to add or remove for it to fit?

I am not asking you to adopt anything. I am asking for ~15 minutes
of direct feedback. Happy to take it by email, a call, or whatever
shape works.

Thank you for reading this far,
Bryan Leonard
Qira LLC
bryanleonard@imagineqira.com

---

## What to watch for in responses

- **The same objection twice.** If two independent people bring up
  the same missing feature, that is a signal. If only one does, wait.
- **"I'd use this if X."** Write down X verbatim. Do not summarize
  it. Summarizing is where you lose the signal.
- **"I don't understand what this is for."** That is the most
  valuable response — it means the pitch is not landing and you
  should rewrite the pitch before building more features.
- **Silence.** Silence from people who expressed frustration about
  the pain before you sent the email means the pain wasn't real
  enough, or they already have a working-enough workaround. Note
  which people go silent — that filters future outreach.

## What NOT to do

- **Do not build features based on a single email.** One person's
  feature request is not a user pattern. Two is the minimum bar
  for any structural change.
- **Do not pitch the BRY-NFET-SX envelope platform in these
  emails.** The platform is how you made `/chat` credible. It is
  not the product being offered. Mixing the two will confuse every
  recipient.
- **Do not pitch NFET-SC-512.** It is research, published
  separately, and belongs in a different conversation.
- **Do not follow up more than once.** If they didn't reply in
  a week, the answer is "not right now." Move on.

## Success criterion

Ten conversations with ten specific humans, each of whom has a
concrete current workflow where `/chat` could fit. Not ten demos.
Not ten signups. Ten conversations.

After those ten conversations you will know one of three things:

1. **The wedge is real.** At least 3 of 10 lit up and said "I
   actually need this." Next step: build the minimum viable
   workflow that matches what those 3 said.
2. **The wedge is wrong but adjacent.** They care about a related
   pain that is not the pitch you sent. Next step: rewrite the
   pitch and try again with 10 more people.
3. **No one cares.** You built a good technical artifact for a
   problem no one has today. Next step: let `/chat` be a public
   technical demo and move on to a different wedge.

All three outcomes are honest. The only wrong outcome is not
running the experiment at all.
