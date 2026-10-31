# Vendors and funding

Shortlist for the external audit of `v0.2.0` ([`scope.md`](scope.md))) and ways to pay for it.

**Rule of this document:** only what has been read in the cited source is stated. The rest appears
as «unverified». **There are no prices**: no vendor publishes rates and no quote has been requested.
The figures are filled in [`budget-timeline.md`](budget-timeline.md)) once there are quotes.

Date of the consultation: 2026-10-30. The pages may have changed since then.

## 1. What can be said about each vendor

«Public reports» = the vendor publishes client reports on its website (with the client's permission).
«Availability» = actual capacity and start dates: **none of them could be checked without
contacting**, so it appears as «unverified» in all cases.

| Vendor | Website | Specialty (per its website) | Public reports | Availability | Location / language |
|---|---|---|---|---|---|
| **Cure53** | <https://cure53.de/> | Pentests and code audits; audits of «infrastructure, platforms and cryptography» (they evaluate algorithms and their implementation, key management) | **Yes**: list of public reports (e.g. *Proton Pass* Browser Addon, Apps & API, 05–06.2023; *1Password Mobile Apps*, 02–03.2022; *ExpressVPN Android Client*, 08.2022; *Gem Wallet Rust Wallet Core*, 09.2026) | Unverified | Germany; English (the website is in English) |
| **Trail of Bits** | <https://trailofbits.com/services/software-assurance/> | Multidisciplinary reviews with a cryptography and *appsec* team; they claim 661 audits and 993 publications | **Yes**: [`trailofbits/publications`](https://github.com/trailofbits/publications) repository with reports per project (e.g. `sigstore-rust`, Oct. 2026) | Unverified | USA; English. Android experience: unverified |
| **NCC Group** | <https://www.nccgroup.com/> | The website lists *Application Security*, *Cryptography & Encryption* and *Penetration Testing* as services | Unverified (no list of reports was located in the consultation) | Unverified | International; English. Android/Rust: unverified |
| **Radically Open Security (ROS)** | <https://www.radicallyopensecurity.com/> | **Non-profit** security consultancy; the website lists code, cryptography and protocol audits | Unverified in this consultation (its website does not enumerate reports on the pages consulted) | Unverified | Netherlands; English. Rust/Android: unverified |
| **X41 D-Sec** | <https://x41-dsec.de/> | Source code audits, pentests, *fuzzing*, research | **Yes**: list of public audits, many for OSTIF (including *Hickory DNS*, a Rust project; also *Mullvad VPN* and *SecureDrop*) | Unverified | Germany; English. Android: unverified |
| **7ASecurity** | <https://7asecurity.com/> | Pentests and code audits, including mobile apps; partner of the OTF Security Lab; «EU-based» | **Yes**: [`/publications`](https://7asecurity.com/publications) (includes reports with *Android app* and *Crypto & Privacy Audit*, e.g. *Noghteha*, 02.2026; and several for OSTIF and OTF) | Unverified | EU; English. Rust: unverified |
| **Include Security** | <https://includesecurity.com/> | Source-assisted application assessments; its website lists *Mobile App Assessments* and *Fuzzing* | Unverified (no list of reports was located) | Unverified | Brooklyn (USA); English |
| **Quarkslab** | <https://www.quarkslab.com/> | Reverse engineering and security; its blog has cryptography, Android and *fuzzing* categories; «since 2026 it is part of Airbus Defence and Space» (per its website) | **Partial**: its blog describes an *mbedTLS* audit carried out at OSTIF's request (2026-10-20); whether they publish a report per client: unverified | Unverified | France; English and French |

Notes:

- The «Location / language» column is indicative (legal notice, domain, addresses or phone numbers on the website;
  for Trail of Bits and NCC Group it was not checked in the consultation). Confirm it before hiring.
- The presence of a report on a similar project (Proton Pass, 1Password) does **not** imply
  experience with the OpenPassword stack (Rust + UniFFI + Compose). It has to be asked.
- «Rust» and «Android» are marked «unverified» when the website does not say so explicitly, even if the
  vendor may have experience.
- Each profile must be completed with the vendor's answer to the template in
  [`budget-timeline.md`](budget-timeline.md)).

## 2. Comparison criteria

| Criterion | What to ask or check | Weight |
|---|---|---|
| Cryptography and Rust | Auditors with experience in AEAD, KDF and STREAM-like *constructions*? Have they reviewed Rust code and UniFFI? | **PENDING** (the project decides) |
| Android | Keystore, biometrics, autofill (`AutofillService`) and *tapjacking*? Previous Android app reports? | **PENDING** |
| Public reports | Do they publish reports? Of projects of this kind? | **PENDING** |
| Re-test included | Does the budget include verification of the fixes? How many rounds and within what deadline? | **PENDING** |
| Permission to publish | Does the contract allow publishing the full report without conditions? With what delay? | **PENDING** (mandatory condition: yes) |
| Deadlines | Start date, duration and date of the preliminary report | **PENDING** |
| Cost | Total amount and discount history for open projects | **PENDING** |
| Language | Language of the report and of the communication (the project writes in Spanish; the public report should be in English) | **PENDING** |
| Team and methodology | Specific people, hours per component, use of *fuzzing* and of source code review | **PENDING** |
| Conflicts of interest | Relationship with supply chain vendors (Google, Mozilla, etc.) or with other managers | **PENDING** |

A comparison table with scores is added here **only when there are quotes**; no scoring is done
on unverified data.

## 3. Funding routes

None has a budget assigned yet. The data come from the official websites (consultation
2026-10-30).

### 3.1 OSTIF (Open Source Technology Improvement Fund)

- Source: <https://ostif.org/get-an-audit/>.
- It is a non-profit organisation that **coordinates** the audit: it defines the scope with you,
  selects the team («according to your needs for experience, quality and cost»), supervises the
  audit and **publishes the report** at the end, after the fixes have been applied.
- Its page states that initial audits «can range from $30,000 to $200,000»
  and that they help projects raise funds and sponsors to cover the total cost or
  share it. It does not say that OSTIF pays for it.
- Published requirements: no call with a date. The first step is **writing to OSTIF**; they ask
  for own checks to have been done beforehand (their security best practices guide on GitHub; this
  package covers it in part with [`internal-review.md`](internal-review.md))).
- Fit with OpenPassword: unverified. Its home talks about projects on which «Internet
  infrastructure» depends; it has not been checked whether they accept a personal password manager.
- Deadline and call date: **no call; open contact**.

### 3.2 OTF Security Lab (formerly called «Red Team Lab»)

- Source: <https://www.opentech.fund/labs/security-lab/>. The URL `…/labs/red-team-lab/` loads the OTF
  home page; the page with the service is **Security Lab**. If the name «Red Team Lab» is still to be
  used in applications, it must be confirmed with OTF.
- What it offers: it funds «software security audits, expert help with known issues and
  architecture and design reviews» and pairs them with trusted partners. It is advertised as a
  free audit for the project. The results are published «as open source».
- Partners listed (some): 0xche, **7ASecurity**, Assured, Atredis Partners, Convocation Research &
  Design (the list is longer).
- **Eligibility, and this is the weak point for OpenPassword:** «if your tool contributes to Internet
  freedom anywhere in the world». OTF's goal is people in contexts of
  repression and censorship. An offline password manager **is not obviously** an Internet freedom
  tool; the fit has to be justified (e.g. journalists and activists with secrets on a
  seizable device) or the route discarded. **Unverified** that they would accept it.
- How to apply: form on their website. Deadline: **no call published** on the page
  consulted (it seems to be a continuous application; unverified).

### 3.3 NLnet (NGI Zero): important change

- **NGI Zero Commons Fund has already closed**: its thirteenth and last call closed on **1 June
  2026** and no new applications are accepted (<https://nlnet.nl/commonsfund/>; NGI Zero Core also
  has its last call closed, <https://nlnet.nl/NGI0/>). The route that had been considered under that
  name **no longer exists as an open fund**.
- Its successor on the NLnet website is **Restack** (<https://nlnet.nl/restack/>; thematic fund, see
  <https://nlnet.nl/themes/>):

  | Data point | Value (per NLnet) |
  |---|---|
  | Amount | R&D grants of **€5,000 to €50,000** the first time |
  | First call | Opened on 3 September 2026, **closes on 3 November 2026 at 12:00 CET** |
  | Following ones | Calls open «every two months», between Q3 2026 and 2030 (specific dates: unverified) |
  | Additional support | Besides the money, they offer «accessibility scanners and **security audits**, reproducible packaging…» (<https://nlnet.nl/restack/>) |
  | Eligible activities | It includes «formal security testing, **security audits**, test setup and continuous integration» (<https://nlnet.nl/restack/eligibility/>) |
  | European dimension | The team with people from Horizon Europe eligible countries must receive **at least 60%** of the funds; there are exceptions for exceptional proposals from outside (same page) |
  | License | Software and content under open licenses (GPL-3.0-or-later complies) (<https://nlnet.nl/propose/>) |
  | Generative AI | They require declaring it; proposals must be «made by humans» (<https://nlnet.nl/propose/>) |
  | Language | Answers in English, in plain text |

- Calendar warning: the date of 3 November 2026 is **4 days** away from the date of this
  consultation. The following calls can be used calmly.
- Fit: the project is open source and user infrastructure («end-user applications»)
  and the European dimension seems to be met if the holder and the spending are in the EU (**confirm**
  the tax residence of the applicant). Whether NLnet pays for or commissions **this** kind of audit:
  unverified; its description of support mentions «security audits» as support, not the
  specific terms.

### 3.4 Summary

| Route | What it covers | Deadline | Status |
|---|---|---|---|
| OSTIF | Coordination and search for funds/sponsorship; public report | No call; open contact | **PENDING**: write |
| OTF Security Lab | Free audit with partners (e.g. 7ASecurity) | No published date | **PENDING**: decide whether there is a fit |
| NLnet Restack (successor of NGI Zero) | Grant of €5,000–€50,000 and possible audit support | **2026-11-03 12:00 CET**; then every ~2 months | **PENDING**: decide and draft |
| Own funds | — | — | **PENDING**: amount |

If an application succeeds, the vendor may come conditioned (OSTIF, OTF and NLnet choose or
propose partners). That affects the table in section 1; each route must accept the
non-negotiable criterion of **permission to publish the report** (OSTIF and OTF already publish by design).

## 4. Next steps

1. Decide which routes are attempted and in what order (project decision).
2. Write to OSTIF with [`scope.md`](scope.md)) and the SHA.
3. Contact 3–4 vendors from section 1 with the template in
   [`budget-timeline.md`](budget-timeline.md)); ask for availability, a team with experience in
   Rust/Android/cryptography and the publication policy.
4. Fill in this profile with the answers and replace «unverified» with the source.
