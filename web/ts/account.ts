import { $ } from "./dom";
import { showWelcome, tourSeen } from "./tour";
import { b64uFromBytes, bytesFromB64u, deriveKey, seal } from "./crypto";
import { humanSize, copy } from "./ui";

// Passkey account flows + the active-shares dashboard, both passkey-only.
// Anonymous behavior is untouched; login exists purely for the dashboard.
// The header icon button opens the #accpanel popover (zero JS to open).

interface MeRec {
  name?: string;
  id?: string;
  accounts?: boolean; // false = this instance has USER_ACCOUNTS off
  open?: boolean;
  admin?: boolean; // first registrant / promoted friends only
  passkeys?: string[]; // credential ids of the signed-in identity
}

interface ShareRow {
  id: string;
  kind: "text" | "bundle";
  burn: boolean;
  expires: number;
  views?: number;
  public?: boolean;
}

// fragment stash: create flow stores <id> -> key fragment client-side so the
// dashboard re-opens shares. Deliberately client-side only - the
// zero-knowledge mandate protects the server boundary, not the local disk
// (same threat model as browser history).
function fragGet(id: string): string {
  try {
    return localStorage.getItem("zp.frag." + id) ?? "";
  } catch {
    return "";
  }
}

function fragPut(id: string, keyB64: string): void {
  try {
    localStorage.setItem("zp.frag." + id, keyB64);
  } catch {
    /* private mode */
  }
}

export function stashForCreate(id: string, keyB64: string): void {
  if (keyB64) fragPut(id, keyB64);
}

function dropFrags(): void {
  try {
    const doomed: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith("zp.frag.")) doomed.push(k);
    }
    for (const k of doomed) localStorage.removeItem(k);
  } catch {
    /* private mode */
  }
}

// full phrase for list meta lines: "expires in 24 h" / "expired"
function expiryText(unixSec: number): string {
  const ms = unixSec * 1000 - Date.now();
  if (!(ms > 0)) return "expired";
  const min = Math.round(ms / 60000);
  if (min < 60) return `expires in ${min} min`;
  const h = Math.round(min / 60);
  if (h < 48) return `expires in ${h} h`;
  return `expires in ${Math.round(h / 24)} d`;
}

export async function refreshMe(): Promise<void> {
  try {
    const res = await fetch("/api/me");
    const me = (await res.json()) as MeRec;
    const reg = $("regbtn") as HTMLButtonElement;
    const login = $("loginbtn") as HTMLButtonElement;
    const poll = $("accpoll") as HTMLElement;

    signedIn = !!me.name;
    isAdmin = me.admin === true;
    document.dispatchEvent(new CustomEvent("zp:me")); // compose re-syncs the public slider (hidden while signed out)
    // USER_ACCOUNTS=false: the whole identity feature is off - the account
    // button and pane go away entirely (the /dash card adapts in loadDash)
    const accountsOff = me.accounts === false;
    ($("accbtn") as HTMLButtonElement).classList.toggle("hidden", accountsOff);
    // header Log out: visible on EVERY page once signed in (not only /dash)
    ($("headerlogout") as HTMLButtonElement).classList.toggle("hidden", !signedIn);
    if (accountsOff) {
      poll.textContent = "accounts are disabled on this instance";
      reg.disabled = true;
      login.disabled = true;
      return; // the button is hidden; nothing else in the pane matters
    }
    // IP hosts cannot hold passkeys: the browser needs a domain RP ID and the
    // server config rejects IPs, so 127.0.0.1 and LAN addresses get the hint
    const host = location.hostname;
    const isIPHost =
      /^(\d{1,3}\.){3}\d{1,3}$/.test(host) ||
      host.startsWith("[") || // bracketed IPv6
      (/^[0-9a-f:]+$/i.test(host) && host.includes(":")); // bare IPv6 like ::1
    const insecure =
      isIPHost ||
      (!window.isSecureContext && host !== "localhost" && !host.endsWith(".localhost"));
    ($("browserhint") as HTMLElement).textContent = isIPHost
      ? "Passkeys don't work on an IP address - open the site over its real domain."
      : "Passkeys need HTTPS (or localhost). You are on an insecure origin - open the site over its real domain.";
    ($("browserhint") as HTMLElement).classList.toggle("hidden", !insecure);
    if (insecure) {
      reg.disabled = true;
      login.disabled = true;
      poll.textContent = "passkeys need HTTPS (or localhost)";
      $("accanon").classList.remove("hidden");
      $("accuser").classList.add("hidden");
      return;
    }
    reg.disabled = false;
    login.disabled = false;
    if (signedIn) {
      // registered view: identity line + dashboard/sign-out + attach row;
      // the whole groups swap keeps the pane a simple two-state surface
      $("accanon").classList.add("hidden");
      $("accuser").classList.remove("hidden");
      poll.classList.add("hidden");
      ($("accwhoname") as HTMLElement).textContent = me.name ?? "";
    } else {
      $("accuser").classList.add("hidden");
      $("accanon").classList.remove("hidden");
      poll.classList.remove("hidden");
      // a valid invite in hand re-opens the registration pane even on a
      // closed instance (the server re-validates at begin/finish)
      const open = me.open !== false || !!inviteToken;
      poll.textContent = inviteToken
        ? "invite link detected - create your account"
        : open ? "create an account - passkey only" : "sign in - new registrations are closed";
      $("reggroup").classList.toggle("hidden", !open);
      $("accor").classList.toggle("hidden", !open); // no choice to divide when only sign-in remains
    }
  } catch {
    /* server unreachable: leave the pane as configured */
  }
}

function accError(msg: string): void {
  const err = $("accerr");
  err.textContent = msg;
  err.classList.remove("hidden");
}

// --- webauthn plumbing ---
// go-webauthn emits CredentialCreation/CredentialRequest JSON whose challenge
// and user id are base64url strings; the browser wants ArrayBuffers.

interface CeremonyShape {
  publicKey?: Record<string, unknown>;
  rp?: { id?: string; name?: string };
  user?: { id?: string; name?: string; displayName?: string };
  challenge?: string;
  pubKeyCredParams?: unknown[];
  timeout?: number;
  excludeCredentials?: Array<{ id?: string }>;
  authenticatorSelection?: unknown;
  attestation?: string;
  userVerification?: string;
}

function creationToPublicKey(options: unknown): PublicKeyCredentialCreationOptions {
  const pk = unwrapPublicKey(options);
  return {
    challenge: bytesFromB64u(pk.challenge ?? ""),
    rp: { id: pk.rp?.id ?? "", name: pk.rp?.name ?? "" },
    user: {
      id: bytesFromB64u(pk.user?.id ?? ""),
      name: pk.user?.name ?? "",
      displayName: pk.user?.displayName ?? (pk.user?.name ?? ""),
    },
    pubKeyCredParams: (pk.pubKeyCredParams ?? [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 },
    ]) as PublicKeyCredentialParameters[],
    timeout: pk.timeout ?? 60000,
    excludeCredentials: (pk.excludeCredentials ?? []).map((c) => ({
      id: bytesFromB64u(c.id ?? ""),
      type: "public-key" as PublicKeyCredentialType,
    })),
    authenticatorSelection: (pk.authenticatorSelection ?? {
      residentKey: "preferred",
      userVerification: "preferred",
    }) as AuthenticatorSelectionCriteria,
    attestation: (pk.attestation ?? "none") as AttestationConveyancePreference,
  };
}

function assertionToPublicKey(options: unknown): PublicKeyCredentialRequestOptions {
  const pk = unwrapPublicKey(options);
  return {
    challenge: bytesFromB64u(pk.challenge ?? ""),
    timeout: pk.timeout ?? 60000,
    userVerification: (pk.userVerification ?? "preferred") as UserVerificationRequirement,
  };
}

function unwrapPublicKey(options: unknown): CeremonyShape {
  const shape = (options ?? {}) as CeremonyShape;
  return (shape.publicKey ?? shape) as CeremonyShape;
}

function attestationBody(c: PublicKeyCredential, sessionId: string): string {
  const res = c.response as AuthenticatorAttestationResponse;
  return JSON.stringify({
    sessionId,
    id: c.id,
    rawId: arrayB64u(c.rawId),
    type: "public-key", // the server-side parser rejects bodies without it
    response: {
      attestationObject: arrayB64u(res.attestationObject),
      clientDataJSON: arrayB64u(res.clientDataJSON),
    },
  });
}

function assertionBody(c: PublicKeyCredential, sessionId: string): string {
  const res = c.response as AuthenticatorAssertionResponse;
  return JSON.stringify({
    sessionId,
    id: c.id,
    rawId: arrayB64u(c.rawId),
    type: "public-key",
    response: {
      authenticatorData: arrayB64u(res.authenticatorData),
      clientDataJSON: arrayB64u(res.clientDataJSON),
      signature: arrayB64u(res.signature),
      userHandle: res.userHandle ? arrayB64u(res.userHandle) : "",
    },
  });
}

function arrayB64u(v: ArrayBuffer | Uint8Array): string {
  return b64uFromBytes(new Uint8Array(v));
}

export async function registerStart(): Promise<boolean> {
  ($("accerr") as HTMLElement).classList.add("hidden");
  try {
    const name = ($("accname") as HTMLInputElement).value;
    const res = await fetch("/api/identity/register/begin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, ...(inviteToken ? { invite: inviteToken } : {}) }),
    });
    if (!res.ok) {
      throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? "register begin failed");
    }
    const { options, sessionId } = (await res.json()) as { options: unknown; sessionId: string };
    const cred = (await navigator.credentials.create({ publicKey: creationToPublicKey(options) })) as PublicKeyCredential;
    const fin = await fetch("/api/identity/register/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: attestationBody(cred, sessionId),
    });
    if (!fin.ok) {
      throw new Error(((await fin.json().catch(() => ({}))) as { error?: string }).error ?? "registration failed");
    }
    ($("accerr") as HTMLElement).classList.add("hidden");
    inviteToken = ""; // burned with the account creation
    await refreshMe();
    return true;
  } catch (e) {
    accError(e instanceof Error ? e.message : "registration failed");
    return false;
  }
}

export async function loginStart(): Promise<boolean> {
  ($("accerr") as HTMLElement).classList.add("hidden");
  try {
    const res = await fetch("/api/identity/login/begin", { method: "POST" });
    if (!res.ok) {
      throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? "login begin failed");
    }
    const { options, sessionId } = (await res.json()) as { options: unknown; sessionId: string };
    const cred = (await navigator.credentials.get({ publicKey: assertionToPublicKey(options) })) as PublicKeyCredential | null;
    if (!cred) throw new Error("no credential returned");
    const fin = await fetch("/api/identity/login/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: assertionBody(cred, sessionId),
    });
    if (!fin.ok) {
      throw new Error(((await fin.json().catch(() => ({}))) as { error?: string }).error ?? "login failed");
    }
    ($("accerr") as HTMLElement).classList.add("hidden");
    await refreshMe();
    return true;
  } catch (e) {
    accError(e instanceof Error ? e.message : "login failed");
    return false;
  }
}

export async function logout(): Promise<void> {
  await fetch("/api/identity/logout", { method: "POST" }).catch(() => {});
  dropFrags();
  await refreshMe();
}

export async function bootAccount(): Promise<void> {
  // fresh registration (signed-out → account): one-time welcome tour; the
  // attach button (signed-in) skips it - an existing account needs no tour.
  // Registering from the /dash anon card's popover with the tour already seen
  // re-enters the dashboard in place instead of leaving the sign-in card up.
  $("regbtn").addEventListener("click", () => {
    void registerStart().then((ok) => {
      if (!ok) return;
      const panel = document.getElementById("accpanel") as HTMLDivElement;
      if (!tourSeen()) {
        panel.hidePopover();
        showWelcome();
      } else if (location.pathname === "/dash") {
        panel.hidePopover();
        void returnToDash();
      }
    });
  });
  $("attachbtn").addEventListener("click", () => void registerStart()); // signed-in: attach another key
  // signing in from the lightbox: straight to the dashboard, no lingering panel
  $("loginbtn").addEventListener("click", () => {
    void loginStart().then((ok) => {
      if (!ok) return; // accError already surfaced the problem
      (document.getElementById("accpanel") as HTMLDivElement).hidePopover();
      location.href = "/dash";
    });
  });
  $("logoutbtn").addEventListener("click", () => void logout());
  // the header button: signed-in users land on /dash (this refreshes the row
  // list); anonymous visitors get the identity popover
  $("accbtn").addEventListener("click", () => {
    if (signedIn) {
      location.href = "/dash";
      return;
    }
    (document.getElementById("accpanel") as HTMLDivElement).showPopover();
  });
  // header Log out: works on every page, mirrors the dashboard action
  $("headerlogout").addEventListener("click", async () => {
    await logout();
    location.reload(); // land signed out
  });
  // statistics refresh whenever the lightbox opens or closes
  const panel = $("accpanel") as HTMLElement;
  panel.addEventListener("toggle", () => {
    if ((panel as HTMLElement & { open: boolean }).open) void refreshMe();
  });
  await refreshMe();
}

// live binding: compose view reads this to gate the public-paste slider
// (accounts only) - updated by refreshMe after every /api/me poll
export let signedIn = false;

// live binding: the config tab is admin-only - refreshMe keeps it in sync
export let isAdmin = false;

// the config tab hides for members without the flag; a persisted config tab
// falls back to shares so nobody strands in a pane they cannot use
function syncAdminTab(): void {
  const tab = document.getElementById("tabconfig");
  if (!tab) return;
  tab.classList.toggle("hidden", !isAdmin);
  const cur = document.querySelector("#dashtabs .dashtab.active") as HTMLElement | null;
  if (!isAdmin && cur?.dataset.tab === "config") dashTab("shares");
}

// invite capability from the fragment: an admin-minted link lands as
// /#invite=<token>; read once, stripped like paste keys (fragments never hit
// server logs), then carried into the register/begin call
export let inviteToken = "";

export function readInviteFragment(): void {
  const m = /^#invite=([A-Za-z0-9_-]{20,44})$/.exec(location.hash);
  if (m?.[1] === undefined) return;
  inviteToken = m[1];
  history.replaceState(null, "", location.pathname + location.search); // strip: the link is single-sight
}

// --- the dashboard page (/dash) ---
// Reuses the standard header/footer/popovers: the compose cards are hidden,
// #dashroot renders rows plus the identity edit. Anonymous visitors get a
// sign-in card instead of an empty page.

function shareURL(r: ShareRow): string {
  return location.origin + "/p/" + r.id + (fragGet(r.id) ? "#" + fragGet(r.id) : "");
}

document.addEventListener("zp:me", syncAdminTab); // refreshMe re-syncs after promote/demote

function dashTab(which: string): void {
  for (const b of document.querySelectorAll("#dashtabs .dashtab[data-tab]")) {
    b.classList.toggle("active", (b as HTMLElement).dataset.tab === which);
  }
  for (const pane of ["pane-shares", "pane-reverse", "pane-account", "pane-config"]) {
    $(pane).classList.toggle("hidden", pane !== "pane-" + which);
  }
  try {
    localStorage.setItem("zp.tab", which);
  } catch {
    /* private mode */
  }
}

// tour exit: /dash re-enters in place (listeners are already bound), any
// other page navigates there
export async function returnToDash(): Promise<void> {
  if (location.pathname !== "/dash") {
    location.assign("/dash");
    return;
  }
  $("dashroot").classList.remove("hidden");
  await loadDash();
}

export async function dashboardPage(): Promise<void> {
  $("gate").classList.add("hidden");
  $("compose").classList.add("hidden");
  $("linkbox").classList.add("hidden");
  $("read").classList.add("hidden");
  $("dashroot").classList.remove("hidden");

  // persisted dashboard tab (default shares; holdings tab view choice)
  let tab = "shares";
  try {
    const saved = localStorage.getItem("zp.tab");
    if (saved === "shares" || saved === "reverse" || saved === "account" || saved === "config") tab = saved;
  } catch {
    /* private mode */
  }
  dashTab(tab);
  for (const b of document.querySelectorAll("#dashtabs .dashtab[data-tab]")) {
    (b as HTMLElement).addEventListener("click", () => dashTab((b as HTMLElement).dataset.tab ?? "shares"));
  }

  $("dashsave").addEventListener("click", () => void saveName());
  // signed-in attach: a new passkey for an existing account - never the
  // welcome tour (that belongs to fresh registrations only)
  $("dashreg").addEventListener("click", () => {
    const btn = $("dashreg") as HTMLButtonElement;
    btn.disabled = true;
    void registerStart().then((ok) => {
      btn.disabled = false;
      // the accpanel (and its #accerr) is closed on /dash - mirror the failure
      if (!ok) return void dashError("adding the passkey failed - check the passkey dialog and try again");
      void loadDash();
    });
  });
  $("dashcreate").addEventListener("click", () => {
    (document.getElementById("accpanel") as HTMLDivElement).showPopover();
  });
  $("dashlogin").addEventListener("click", () => {
    // errors must land in #dasherr (the accpanel is closed on /dash);
    // registerStart swallows into accError, so mirror the failed state here
    void loginStart().then((ok) => {
      if (ok) return void loadDash();
      dashError("sign in failed - check the passkey dialog and try again");
    });
  });

  // reverse shares: create + rows (uplinks carry the key in the fragment, so
  // the stash is what lets this browser open and read the arriving files)
  $("revform").addEventListener("submit", (e) => {
    e.preventDefault();
    void (async () => {
      const btn = $("revcreate") as HTMLButtonElement;
      btn.disabled = true;
      try {
        const slug = ($("revslug") as HTMLInputElement).value.trim().toLowerCase();
        const ttl = ($("revttl") as HTMLInputElement).value.trim();
        const mb = Number(($("revsize") as HTMLInputElement).value);
        const pass = ($("revpass") as HTMLInputElement).value;
        let salt = "";
        let check = "";
        let keyB64 = "";
        if (pass) {
          // passphrase uplink: the server stores the public salt + a sealed
          // verifier; the passphrase itself never leaves this tab
          salt = b64uFromBytes(crypto.getRandomValues(new Uint8Array(16)));
          const key = await deriveKey(pass, bytesFromB64u(salt));
          check = await seal(key, "zeropaste-rshare");
        } else {
          keyB64 = freshKeyB64(); // fragment mode: the uplink rides the key
        }
        const res = await fetch("/api/rshare", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ slug, ttl, maxSize: Math.round(mb * 1024 * 1024), salt, check }),
        });
        if (!res.ok) {
          throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? "create failed");
        }
        if (keyB64) fragPut("rv:" + slug, keyB64); // fragment mode only
        ($("revslug") as HTMLInputElement).value = "";
        ($("revpass") as HTMLInputElement).value = "";
        await renderRshares();
      } catch (e) {
        dashError(e instanceof Error ? e.message : "create failed");
      } finally {
        btn.disabled = false;
      }
    })();
  });

  wireConfig();
  await loadDash();
}

// ---- admin config tab ----

interface CfgKnob {
  name: string;
  kind: string;
  source: string;
  set?: boolean;
  value?: boolean | number | string;
}

interface CfgView {
  knobs: CfgKnob[];
  restartNeeded: boolean;
}

// whether the server holds a gate key (CREATE_KEY set flag from the last view)
let keySet = false;
// the last server view (Discard repaints from it) and its form snapshot: the
// save bar compares the live form against this to tell dirty from clean
let lastView: CfgView | null = null;
let cfgSnapshot = "";
let pendingRestart = false; // the saved file differs from what this boot loaded
let cfgBusy = false; // a save/reboot is in flight - keep the bar's buttons down
let meId = ""; // the signed-in identity: marks "you" in the admins list

function cfgError(msg: string): void {
  const err = $("cfgerr");
  err.textContent = msg;
  err.classList.remove("hidden");
}

function peopleError(msg: string): void {
  const err = $("peopleerr");
  err.textContent = msg;
  err.classList.remove("hidden");
}

function delay(ms: number): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>();
  setTimeout(resolve, ms);
  return promise;
}

// error body override: {"error": "..."} is the server's only shape
async function resErr(res: Response, fallback: string): Promise<string> {
  const raw: unknown = await res.json().catch(() => null);
  if (raw && typeof raw === "object" && "error" in raw && typeof raw.error === "string") return raw.error;
  return fallback;
}

function pickedValue(group: string): string {
  return ($(group) as HTMLElement).querySelector<HTMLInputElement>("input[type=radio]:checked")?.value ?? "open";
}

// the gate passphrase field belongs to passphrase mode; the forget switch to
// the other modes, and only while a key is stored
function syncKeyRows(): void {
  const passMode = pickedValue("cfgaccess") === "passphrase";
  $("cfgkeyrow").classList.toggle("hidden", !passMode);
  $("cfgforgetrow").classList.toggle("hidden", passMode || !keySet);
}

// limits show MB, the wire carries bytes: an untouched field sends its exact
// stored byte count back, so the 2-decimal display never drifts the value
function setMB(id: string, bytes: number): void {
  const el = $(id) as HTMLInputElement;
  const shown = String(Math.round((bytes / 1048576) * 100) / 100);
  el.value = shown;
  el.dataset.shown = shown;
  el.dataset.bytes = String(bytes);
}

function mbBytes(id: string): number {
  const el = $(id) as HTMLInputElement;
  return el.value === el.dataset.shown ? Number(el.dataset.bytes) : Math.round(Number(el.value) * 1048576);
}

const ADMIN_ROLE = "admin - settings, people and invites";
const MEMBER_ROLE = "member - shares and drop links";

interface AdminRow {
  id: string;
  name: string;
  admin: boolean;
}

// admins list: one switch per stored identity; demoting the last admin draws
// the server's 400 into #peopleerr and the switch keeps its stored state
async function renderAdmins(): Promise<void> {
  const box = $("cfgadmins") as HTMLElement;
  const res = await fetch("/api/admin/identities").catch(() => null);
  if (!res?.ok) return;
  const rows = ((await res.json()) as { identities: AdminRow[] }).identities;
  box.textContent = "";
  for (const idn of rows) {
    const label = idn.name || idn.id;
    const name = document.createElement("span");
    name.textContent = label;
    const sw = document.createElement("button");
    sw.type = "button";
    sw.className = "switch";
    sw.setAttribute("role", "switch");
    sw.setAttribute("aria-checked", String(idn.admin));
    sw.setAttribute("aria-label", "admin rights: " + label);
    const row = itemRow(
      idn.admin ? IC.shield : IC.user,
      name,
      idn.id === meId ? [chip("you", "accent")] : [],
      idn.admin ? ADMIN_ROLE : MEMBER_ROLE,
      [sw],
    );
    sw.addEventListener("click", () => {
      sw.disabled = true;
      $("peopleerr").classList.add("hidden");
      void (async () => {
        const res = await fetch("/api/admin/identities/" + idn.id, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ admin: !idn.admin }),
        });
        sw.disabled = false;
        if (!res.ok) {
          peopleError(await resErr(res, "change failed"));
          return;
        }
        idn.admin = !idn.admin;
        sw.setAttribute("aria-checked", String(idn.admin));
        (row.querySelector(".itemicon") as HTMLElement).innerHTML = idn.admin ? IC.shield : IC.user; // static icon markup only
        (row.querySelector(".itemsub") as HTMLElement).textContent = idn.admin ? ADMIN_ROLE : MEMBER_ROLE;
        await refreshMe(); // a self-change flips the config tab visibility
      })();
    });
    box.append(row);
  }
}

interface InviteRow {
  token: string;
  uses: number;
  maxUses: number;
}

async function renderInvites(): Promise<void> {
  const box = $("invitelist") as HTMLElement;
  const res = await fetch("/api/admin/invites").catch(() => null);
  if (!res?.ok) return;
  const rows = ((await res.json()) as { invites: InviteRow[] }).invites;
  box.textContent = "";
  for (const inv of rows) {
    const name = document.createElement("span");
    name.textContent = "invite " + inv.token.slice(0, 8) + "…";
    const cp = iconBtn("Copy invite link", IC.copy);
    cp.addEventListener("click", () => void copy(location.origin + "/#invite=" + inv.token, cp));
    const del = iconBtn("Revoke invite", IC.del, "rowicon danger");
    del.addEventListener("click", () => {
      del.disabled = true;
      void (async () => {
        await fetch("/api/admin/invites/" + inv.token, { method: "DELETE" }).catch(() => {});
        await renderInvites();
      })();
    });
    const left = inv.maxUses - inv.uses;
    box.append(itemRow(IC.link, name, [], `${inv.uses} of ${inv.maxUses} used · ${left} left`, [cp, del]));
  }
}

// paint the form from a server view, then snapshot it: the save bar measures
// every later edit against that snapshot
function paintConfig(v: CfgView): void {
  lastView = v;
  const by: Record<string, CfgKnob> = Object.fromEntries(v.knobs.map((k) => [k.name, k]));
  const pick = (group: string, val: string): void => {
    for (const el of ($(group) as HTMLElement).querySelectorAll<HTMLInputElement>("input[type=radio]")) {
      el.checked = el.value === val;
    }
  };
  pick("cfgaccess", String(by["PASTE_ACCESS"]?.value ?? "open"));
  pick("cfgregroup", String(by["REGISTRATION"]?.value ?? "open"));
  keySet = by["CREATE_KEY"]?.set === true;
  const key = $("cfgcreate") as HTMLInputElement;
  key.value = ""; // a stored key is never echoed back
  key.placeholder = keySet ? "stored - type to replace it" : "required - type a passphrase";
  $("cfgforget").setAttribute("aria-checked", "false");
  syncKeyRows();
  $("cfgpublic").setAttribute("aria-checked", String(by["PUBLIC_PASTES"]?.value === true));
  ($("cfgttl") as HTMLInputElement).value = String(by["MAX_TTL_DAYS"]?.value ?? "");
  ($("cfgshares") as HTMLInputElement).value = String(by["MAX_SHARES_PER_ACCOUNT"]?.value ?? "");
  setMB("cfgupload", Number(by["MAX_UPLOAD"]?.value ?? 0));
  setMB("cfgchunk", Number(by["CHUNK"]?.value ?? 0));
  pendingRestart = v.restartNeeded;
  cfgSnapshot = JSON.stringify(cfgBody());
  syncCfgBar();
}

// the form as a PUT body: every knob, plus createKey only when typed in
// passphrase mode (replace) or when the forget switch is on elsewhere (clear)
function cfgBody(): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  const access = pickedValue("cfgaccess");
  body.pasteAccess = access;
  const typed = ($("cfgcreate") as HTMLInputElement).value;
  if (access === "passphrase" && typed) body.createKey = typed;
  if (access !== "passphrase" && $("cfgforget").getAttribute("aria-checked") === "true") body.createKey = "";
  body.registration = pickedValue("cfgregroup");
  body.publicPastes = $("cfgpublic").getAttribute("aria-checked") === "true";
  body.maxTtlDays = Number(($("cfgttl") as HTMLInputElement).value);
  body.maxShares = Math.round(Number(($("cfgshares") as HTMLInputElement).value));
  body.maxUpload = mbBytes("cfgupload");
  body.chunk = mbBytes("cfgchunk");
  return body;
}

// save bar: clean / dirty (unsaved edits) / pending (saved, waiting for a reboot)
function syncCfgBar(): void {
  const dirty = JSON.stringify(cfgBody()) !== cfgSnapshot;
  const apply = $("cfgapply") as HTMLButtonElement;
  ($("cfgsave") as HTMLButtonElement).disabled = cfgBusy || !dirty;
  apply.disabled = cfgBusy || (!dirty && !pendingRestart);
  apply.textContent = !dirty && pendingRestart ? "Reboot now" : "Save + reboot";
  $("cfgdiscard").classList.toggle("hidden", !dirty || cfgBusy);
  const bar = $("cfgbar");
  bar.classList.toggle("dirty", dirty);
  bar.classList.toggle("pending", !dirty && pendingRestart);
  if (!cfgBusy) {
    $("cfgnote").textContent = dirty ? "unsaved changes" : pendingRestart ? "saved - reboot to apply" : "no unsaved changes";
  }
}

function wireConfig(): void {
  void (async () => {
    const res = await fetch("/api/admin/config").catch(() => null);
    if (res?.ok) {
      paintConfig((await res.json()) as CfgView);
      void renderInvites();
    } else {
      // non-admin session or server unreachable: keep the card head, drop the
      // form, the bar and the people card so the error line is the message
      $("cfgbody").classList.add("hidden");
      $("cfgbar").classList.add("hidden");
      $("cfgpeople").classList.add("hidden");
      cfgError("configuration is unavailable for this session");
    }
  })();

  const save = async (apply: boolean): Promise<void> => {
    $("cfgerr").classList.add("hidden");
    const draft = cfgBody();
    const dirty = JSON.stringify(draft) !== cfgSnapshot;
    if (dirty && draft.pasteAccess === "passphrase" && !draft.createKey && !keySet) {
      cfgError("passphrase mode needs a gate passphrase - type one into the field");
      ($("cfgcreate") as HTMLInputElement).focus();
      return;
    }
    cfgBusy = true;
    syncCfgBar();
    try {
      if (dirty) {
        $("cfgnote").textContent = "saving...";
        const res = await fetch("/api/admin/config", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(draft),
        });
        if (!res.ok) {
          throw new Error(await resErr(res, "save failed"));
        }
        paintConfig((await res.json()) as CfgView);
      }
      if (apply) {
        // 409 = a reboot is already scheduled: keep waiting for it
        const applyRes = await fetch("/api/admin/apply", { method: "POST" });
        if (!applyRes.ok && applyRes.status !== 409) {
          throw new Error(await resErr(applyRes, "reboot failed"));
        }
        $("cfgnote").textContent = "server is rebooting with the saved configuration...";
        for (let i = 0; i < 20; i++) {
          await delay(500);
          const check = await fetch("/api/gate").catch(() => null);
          if (check?.ok) {
            location.reload();
            return;
          }
        }
        throw new Error("server did not come back within 10s - check the instance");
      }
    } catch (e) {
      cfgError(e instanceof Error ? e.message : "save failed");
    } finally {
      cfgBusy = false;
      syncCfgBar();
    }
  };
  $("cfgsave").addEventListener("click", () => void save(false));
  $("cfgapply").addEventListener("click", () => void save(true));
  $("cfgdiscard").addEventListener("click", () => {
    $("cfgerr").classList.add("hidden");
    if (lastView) paintConfig(lastView);
  });
  // switches flip their own aria-checked, then the bar re-measures dirtiness
  for (const id of ["cfgpublic", "cfgforget"]) {
    $(id).addEventListener("click", () => {
      const sw = $(id);
      sw.setAttribute("aria-checked", sw.getAttribute("aria-checked") === "true" ? "false" : "true");
      syncCfgBar();
    });
  }
  $("cfgaccess").addEventListener("change", syncKeyRows);
  // typed values and radio picks bubble up here
  $("confedit").addEventListener("input", syncCfgBar);
  $("confedit").addEventListener("change", syncCfgBar);

  // invites: mint a link, show it once, keep the live list under it
  $("invcreate").addEventListener("click", () => {
    void (async () => {
      const btn = $("invcreate") as HTMLButtonElement;
      btn.disabled = true;
      $("peopleerr").classList.add("hidden");
      try {
        const res = await fetch("/api/admin/invites", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ uses: Math.max(1, Math.round(Number(($("invcfg") as HTMLInputElement).value) || 1)) }),
        });
        if (!res.ok) {
          throw new Error(await resErr(res, "invite create failed"));
        }
        const { token } = (await res.json()) as { token: string };
        const out = $("invitelink") as HTMLInputElement;
        out.value = location.origin + "/#invite=" + token;
        $("inviteout").classList.remove("hidden");
        out.focus();
        out.select();
        await renderInvites();
      } catch (e) {
        peopleError(e instanceof Error ? e.message : "invite create failed");
      } finally {
        btn.disabled = false;
      }
    })();
  });
  $("invcopy").addEventListener("click", () => void copy(($("invitelink") as HTMLInputElement).value, $("invcopy")));
  $("invitelink").addEventListener("focus", (e) => (e.target as HTMLInputElement).select());
}

async function saveName(): Promise<void> {
  try {
    const res = await fetch("/api/identity/name", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: ($("dashname") as HTMLInputElement).value }),
    });
    if (!res.ok) {
      throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? "name save failed");
    }
    ($("dasherr") as HTMLElement).classList.add("hidden");
    await loadDash();
  } catch (e) {
    dashError(e instanceof Error ? e.message : "name save failed");
  }
}

function dashError(msg: string): void {
  const err = $("dasherr");
  err.textContent = msg;
  err.classList.remove("hidden");
}

// uplink keys: 32 fresh bytes, base64url - same shape as paste fragments
function freshKeyB64(): string {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  let s = "";
  for (const b of raw) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface RevRow {
  slug: string;
  maxSize: number;
  expires: number;
  uploads: number;
  bytes: number;
  pass?: boolean; // passphrase uplink: bare links, no stashed fragment
  items: { id: string; size: number; created: number }[];
}

// inline icon snippets (static strings only; never user data) - lucide shapes
const SVG = (inner: string): string =>
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
  inner +
  "</svg>";
const IC = {
  chev: SVG('<polyline points="6 9 12 15 18 9"></polyline>'),
  copy: SVG('<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>'),
  open: SVG('<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line>'),
  del: SVG('<polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>'),
  text: SVG('<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"></path><path d="M14 2v4a2 2 0 0 0 2 2h4"></path><path d="M10 9H8"></path><path d="M16 13H8"></path><path d="M16 17H8"></path>'),
  files: SVG('<path d="M20 7h-3a2 2 0 0 1-2-2V2"></path><path d="M9 18a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h7l4 4v10a2 2 0 0 1-2 2Z"></path><path d="M3 7.6v12.8A1.6 1.6 0 0 0 4.6 22h9.8"></path>'),
  inbox: SVG('<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"></polyline><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path>'),
  key: SVG('<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"></path><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"></circle>'),
  link: SVG('<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>'),
  user: SVG('<circle cx="12" cy="8" r="5"></circle><path d="M20 21a8 8 0 0 0-16 0"></path>'),
  shield: SVG('<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"></path><path d="m9 12 2 2 4-4"></path>'),
};

function iconBtn(aria: string, svg: string, cls = "rowicon"): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = cls;
  b.setAttribute("aria-label", aria);
  b.title = aria;
  b.innerHTML = svg; // static icon markup only
  return b;
}

// icon action that opens a share/drop link in a new tab
function openLink(href: string, aria: string): HTMLAnchorElement {
  const a = document.createElement("a");
  a.className = "rowicon";
  a.href = href;
  a.target = "_blank";
  a.rel = "noopener";
  a.title = aria;
  a.setAttribute("aria-label", aria);
  a.innerHTML = IC.open; // static icon markup only
  return a;
}

// one list language for every dashboard collection: icon tile + title line
// (name + chips) + muted meta line + icon actions. Callers build the name
// element (link, button or span) and fill user data via textContent only.
function itemRow(icon: string, name: HTMLElement, chips: HTMLElement[], sub: string, acts: HTMLElement[]): HTMLDivElement {
  const row = document.createElement("div");
  row.className = "item";
  const head = document.createElement("div");
  head.className = "itemhead";
  const ico = document.createElement("span");
  ico.className = "itemicon";
  ico.innerHTML = icon; // static icon markup only
  const main = document.createElement("div");
  main.className = "itemmain";
  const title = document.createElement("div");
  title.className = "itemtitle";
  name.classList.add("itemname");
  title.append(name, ...chips);
  const meta = document.createElement("span");
  meta.className = "itemsub";
  meta.textContent = sub;
  main.append(title, meta);
  const box = document.createElement("div");
  box.className = "itemacts";
  box.append(...acts);
  head.append(ico, main, box);
  row.append(head);
  return row;
}

function chip(text: string, tone = ""): HTMLSpanElement {
  const c = document.createElement("span");
  c.className = tone ? "chipmeta " + tone : "chipmeta";
  c.textContent = text;
  return c;
}

// dashed empty-state box (the compose dropzone's language) with an optional CTA
function emptyState(title: string, text: string, cta?: { href: string; label: string }): HTMLDivElement {
  const box = document.createElement("div");
  box.className = "itemempty";
  const b = document.createElement("b");
  b.textContent = title;
  box.append(b, text);
  if (cta) {
    const a = document.createElement("a");
    a.href = cta.href;
    a.textContent = cta.label;
    box.append(document.createElement("br"), a);
  }
  return box;
}

async function renderRshares(): Promise<void> {
  const box = $("revlist") as HTMLElement;
  box.textContent = "";
  const res = await fetch("/api/rshares");
  if (!res.ok) return;
  const rows = (await res.json()) as RevRow[];
  if (rows.length === 0) {
    box.append(emptyState("no drop links yet", "create one above and send it to whoever should upload to you"));
    return;
  }
  for (const r of rows) {
    // pass mode never stashes a fragment; ignore leftover stash entries from
    // a same-slug fragment-mode predecessor wiped and recreated with a pass
    const keyB64 = r.pass ? "" : fragGet("rv:" + r.slug);
    const uplink = r.pass
      ? location.origin + "/r/" + r.slug
      : location.origin + "/r/" + r.slug + (keyB64 ? "#" + keyB64 : "");
    const valid = r.pass || keyB64 !== "";

    const name = document.createElement("button");
    name.type = "button";
    name.textContent = "/" + r.slug;
    const chips: HTMLElement[] = [];
    if (r.pass) chips.push(chip("passphrase", "accent"));
    if (!valid) chips.push(chip("key missing", "burn"));
    // text-only arrivals carry no byte size - a "0 B" total would read as empty
    const files =
      r.uploads === 0
        ? "awaiting files"
        : `${r.uploads} file${r.uploads === 1 ? "" : "s"}` + (r.bytes > 0 ? ` · ${humanSize(r.bytes)}` : "");
    const cp = iconBtn("Copy drop link", IC.copy);
    cp.addEventListener("click", () => void copy(uplink, cp));
    const del = iconBtn("Delete drop link", IC.del, "rowicon danger");
    del.addEventListener("click", () => {
      if (!confirm("Delete this drop link? The link dies and all collected files are removed.")) return;
      del.disabled = true;
      void (async () => {
        const res = await fetch("/api/rshare/" + r.slug, { method: "DELETE" });
        if (!res.ok) {
          del.disabled = false;
          dashError("delete failed");
          return;
        }
        try {
          localStorage.removeItem("zp.frag.rv:" + r.slug);
          localStorage.removeItem("zp.tab-rev:" + r.slug);
        } catch {
          /* private mode */
        }
        await renderRshares();
      })();
    });
    const chev = iconBtn("Show uploads", IC.chev, "rowicon chev");
    chev.setAttribute("aria-expanded", "false");
    const row = itemRow(
      IC.inbox,
      name,
      chips,
      `${files} · ${expiryText(r.expires)} · max ${humanSize(r.maxSize)}`,
      [cp, openLink(uplink, "Open drop link"), del, chev],
    );

    // collapsible detail: the drop link itself, key repair, arrivals
    const detail = document.createElement("div");
    detail.className = "itemdetail hidden";
    const linkLabel = document.createElement("span");
    linkLabel.className = "detaillabel";
    linkLabel.textContent = r.pass ? "drop link - share the passphrase over another channel" : "drop link - the key rides the #fragment";
    const field = document.createElement("div");
    field.className = "linkfield";
    const linkInput = document.createElement("input");
    linkInput.type = "text";
    linkInput.readOnly = true;
    linkInput.value = uplink;
    linkInput.setAttribute("aria-label", "drop link");
    linkInput.addEventListener("focus", () => linkInput.select());
    field.append(linkInput);
    detail.append(linkLabel, field);
    if (!valid) {
      const warn = document.createElement("span");
      warn.className = "revwarn";
      warn.textContent = "this browser lost the key - paste the original drop link (or its #key) to read arrivals here";
      const fix = document.createElement("div");
      fix.className = "revfix";
      const inp = document.createElement("input");
      inp.type = "text";
      inp.placeholder = "paste the drop link or just the #key";
      inp.autocomplete = "off";
      inp.spellcheck = false;
      const repair = document.createElement("button");
      repair.type = "button";
      repair.textContent = "Repair";
      repair.addEventListener("click", () => {
        // recovery: the key never left the sender-side links, so it has to
        // come back from wherever one still lives (chat, another device)
        const raw = inp.value.trim();
        const key = raw.includes("http") ? raw.slice(raw.lastIndexOf("#") + 1).trim() : raw;
        if (!/^[A-Za-z0-9_-]{10,}$/.test(key)) {
          warn.textContent = "that is not an intact drop link or key - keep the part after #";
          return;
        }
        fragPut("rv:" + r.slug, key);
        void renderRshares();
      });
      fix.append(inp, repair);
      detail.append(warn, fix);
    }
    const arrLabel = document.createElement("span");
    arrLabel.className = "detaillabel";
    arrLabel.textContent = r.items.length === 0 ? "arrivals - nothing uploaded yet" : "arrivals";
    detail.append(arrLabel);
    for (const it of r.items) {
      const ar = document.createElement("div");
      ar.className = "subrow";
      const ico = document.createElement("span");
      ico.className = "subico";
      ico.innerHTML = it.size > 0 ? IC.files : IC.text; // static icon markup only
      const fid = document.createElement(valid ? "a" : "span");
      fid.textContent = "/p/" + it.id;
      if (fid instanceof HTMLAnchorElement) {
        fid.href = location.origin + "/p/" + it.id + (r.pass ? "" : "#" + keyB64);
        fid.target = "_blank";
        fid.rel = "noopener";
      } else {
        fid.className = "missing";
      }
      const fsize = document.createElement("span");
      fsize.className = "subsize";
      fsize.textContent = it.size > 0 ? humanSize(it.size) : "text";
      ar.append(ico, fid, fsize);
      detail.append(ar);
    }
    const toggle = (): void => {
      const closed = detail.classList.toggle("hidden");
      chev.classList.toggle("open", !closed);
      chev.setAttribute("aria-expanded", String(!closed));
    };
    chev.addEventListener("click", toggle);
    name.addEventListener("click", toggle);
    row.append(detail);
    box.append(row);
  }
}

async function loadDash(): Promise<void> {
  $("dasherr").classList.add("hidden");
  const me = (await (await fetch("/api/me")).json()) as MeRec;
  const accountsOff = me.accounts === false;
  const anon = !me.name;
  $("dashhead").classList.toggle("hidden", anon);
  $("dashanon").classList.toggle("hidden", !anon);
  $("dashedit").classList.toggle("hidden", anon);
  if (anon) {
    const title = $("dashanon").querySelector(":scope > b") as HTMLElement;
    // registration closed: only the sign-in path is real on this card
    const canRegister = !accountsOff && me.open !== false;
    $("dashcreate").classList.toggle("hidden", !canRegister);
    if (accountsOff) {
      // no sign-in button, no invite: the instance runs anonymous-only
      $("dashlogin").classList.add("hidden");
      title.textContent = "anonymous paste box";
      $("dashanontext").textContent = "This instance runs anonymous-only - accounts are disabled. Every paste stands on its own link and expiry.";
    } else {
      $("dashlogin").classList.remove("hidden");
      title.textContent = "your shares live here";
      $("dashanontext").textContent = canRegister
        ? "Create an account or sign in with a passkey to see, copy and delete your active shares."
        : "Sign in with your passkey to see, copy and delete your active shares.";
    }
    $("dashtabs").classList.add("hidden");
    $("dashpanes").classList.add("hidden");
    $("dashanon").classList.remove("hidden");
    return; // sign-in card is up
  }
  $("dashanon").classList.add("hidden");
  $("dashtabs").classList.remove("hidden");
  $("dashpanes").classList.remove("hidden");
  isAdmin = me.admin === true;
  meId = me.id ?? "";
  syncAdminTab();
  void renderRshares().catch(() => {
    dashError("could not list reverse shares");
  });
  if (isAdmin) void renderAdmins(); // needs meId for the "you" marker

  const nameBox = $("dashname") as HTMLInputElement;
  nameBox.value = me.name ?? "";
  const list = $("passkeylist") as HTMLElement;
  list.textContent = "";
  const keys = me.passkeys ?? [];
  keys.forEach((id, i) => {
    const name = document.createElement("span");
    name.textContent = keys.length === 1 ? "passkey" : `passkey ${i + 1}`;
    name.title = id;
    list.append(itemRow(IC.key, name, [], "credential " + (id.length > 20 ? id.slice(0, 18) + "…" : id), []));
  });
  if (keys.length === 0) list.append(emptyState("no passkeys yet", "add one to sign in from this device"));

  const rowsBox = $("dashrows") as HTMLElement;
  rowsBox.textContent = "";
  const res = await fetch("/api/shares");
  const rows = (await res.json()) as ShareRow[];
  const count = $("sharecount");
  count.textContent = `${rows.length} active`;
  count.classList.toggle("hidden", rows.length === 0);
  if (rows.length === 0) {
    rowsBox.append(
      emptyState("no active shares", "share a paste or a file bundle while signed in and it shows up here", {
        href: "/",
        label: "create a paste",
      }),
    );
    return;
  }
  for (const r of rows) {
    const url = shareURL(r);
    const name = document.createElement("a");
    name.href = url;
    name.target = "_blank";
    name.rel = "noopener";
    name.textContent = r.kind === "bundle" ? "file bundle" : "text paste";
    const chips: HTMLElement[] = [];
    if (r.burn) chips.push(chip("burn after reading", "burn"));
    if (r.public) chips.push(chip("public", "accent"));
    const views = r.views ?? 0;
    const cp = iconBtn("Copy share link", IC.copy);
    cp.addEventListener("click", () => void copy(url, cp));
    const del = iconBtn("Delete share", IC.del, "rowicon danger");
    del.addEventListener("click", () => {
      if (!confirm("Delete this share? The link stops working for everyone, including you.")) return;
      del.disabled = true;
      void (async () => {
        const res = await fetch("/api/paste/" + r.id, { method: "DELETE" });
        if (!res.ok) {
          del.disabled = false;
          dashError("delete failed - the share may already be gone");
          return;
        }
        await loadDash(); // rows recompute live; the deleted one is gone
      })();
    });
    rowsBox.append(
      itemRow(
        r.kind === "bundle" ? IC.files : IC.text,
        name,
        chips,
        `/p/${r.id} · ${views} view${views === 1 ? "" : "s"} · ${expiryText(r.expires)}`,
        [cp, openLink(url, "Open share"), del],
      ),
    );
  }
}
