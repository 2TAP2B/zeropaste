import { $ } from "./dom";
import { show } from "./ui";

// ---- welcome tour (v0.12.3) ----
// A fresh registration lands on a one-time welcome card: take a short tour
// (shares + ttl, files, reverse shares, dashboard) or skip straight to the
// dashboard. Seen-flag lives in localStorage zp.tour - per browser, like the
// theme; a returning sign-in never re-triggers it.

interface TourStep {
  icon: string;
  title: string;
  text: string;
}

const steps: TourStep[] = [
  {
    icon: '<rect x="4" y="11" width="16" height="10" rx="2" ry="2"></rect><path d="M8 11V7a4 4 0 0 1 8 0v4"></path>',
    title: "shares that die",
    text: "Type or paste anything - it is encrypted in your browser and the link carries the key. Pick how long it lives; burn-after-reading deletes it on first read.",
  },
  {
    icon: '<rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><path d="M21 15l-5-5L5 21"></path>',
    title: "files and images",
    text: "Drop files or paste screenshots: previews, a lightbox, resumable chunked uploads - all encrypted exactly like the text.",
  },
  {
    icon: '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"></polyline><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path>',
    title: "reverse shares",
    text: "Need something back? Create a drop link: friends upload through it and you collect the arrivals on your dashboard - their content stays unreadable to the server.",
  },
  {
    icon: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle>',
    title: "your dashboard",
    text: "Everything you shared sits under /dash with copy, expiry and delete. Your passkey is the account; the server never sees a key or a passphrase.",
  },
];

export function tourSeen(): boolean {
  try {
    return localStorage.getItem("zp.tour") === "done";
  } catch {
    return false; // private mode: show the tour, never persist
  }
}

function markTourDone(): void {
  try {
    localStorage.setItem("zp.tour", "done");
  } catch {
    /* private mode */
  }
}

const WELCOME_ICON =
  '<rect x="4" y="11" width="16" height="10" rx="2" ry="2"></rect><path d="M8 11V7a4 4 0 0 1 8 0v4"></path>';
const WELCOME_TEXT =
  "everything you share is encrypted in your browser - the server stores ciphertext only. take the 60 second tour?";

let step = -1; // -1: the welcome card; 0..3: tour steps

function paint(): void {
  const ico = $("welico");
  const title = $("weltitle");
  const text = $("weltext");
  const dots = $("weldots");
  const back = $("welback");
  const next = $("welnext");
  if (step < 0) {
    ico.innerHTML = WELCOME_ICON;
    title.textContent = "hey, welcome to zeropaste";
    text.textContent = WELCOME_TEXT;
    dots.classList.add("hidden");
    back.classList.add("hidden");
    next.textContent = "take a tour";
    return;
  }
  const s = steps[step];
  if (!s) return; // belt: step is always within bounds
  ico.innerHTML = s.icon;
  title.textContent = s.title;
  text.textContent = s.text;
  dots.classList.remove("hidden");
  dots.textContent = "";
  for (let i = 0; i < steps.length; i++) {
    const d = document.createElement("span");
    if (i === step) d.className = "on";
    dots.append(d);
  }
  back.classList.toggle("hidden", step === 0);
  next.textContent = step === steps.length - 1 ? "to the dashboard" : "next";
}

function finishRoute(): void {
  const panel = document.getElementById("accpanel") as HTMLDivElement | null;
  if (panel?.matches("[popover]")) panel.hidePopover();
}

export function showWelcome(): void {
  step = -1;
  paint();
  show("welcome");
}

// wireWelcome binds the static card once; exit() routes the end of the tour
// (skip or last step) to the dashboard - supplied by the boot code so this
// module stays decoupled from the dashboard internals.
export function wireWelcome(exit: () => void): void {
  const done = (): void => {
    markTourDone();
    finishRoute();
    exit();
  };
  $("welnext").addEventListener("click", () => {
    if (step < steps.length - 1) {
      step++;
      paint();
      return;
    }
    done();
  });
  $("welback").addEventListener("click", () => {
    if (step > 0) {
      step--;
      paint();
    }
  });
  $("welskip").addEventListener("click", done);
}
