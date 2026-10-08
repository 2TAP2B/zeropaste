import type { JSX } from "preact";
import { show, view, sessionName } from "./state";
import { theme, toggleTheme, applyTheme } from "./theme";
import { Gate, ComposeView, LinkView } from "./compose";
import { ReadView } from "./read";
import { DashPage } from "./dash";
import { SelfCheck } from "./selfcheck";
import { $ } from "./dom";
import { refreshMe, loginStart, logout, registerStart } from "./account";
import { render } from "preact";

applyTheme(theme.value); // paint the theme before anything mounts

// the static account lightbox (outside #app)
$("regbtn").addEventListener("click", () => void registerStart());
$("loginbtn").addEventListener("click", () => void loginStart());
$("logoutbtn").addEventListener("click", () => void logout());
const panel = document.getElementById("accpanel") as HTMLDivElement | null;
panel?.addEventListener("toggle", () => {
  if ((panel as unknown as { open: boolean }).open) void refreshMe();
});

function Header(): JSX.Element {
  return (
    <header class="top">
      <a class="brand" href="/">zeropaste <span>/ zero-knowledge pastes</span></a>
      <button type="button" class="theme-toggle" id="theme" aria-label="Toggle light and dark theme" title="Toggle theme" onClick={() => toggleTheme()}>
        <svg class="moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
        <svg class="sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"></circle><path class="rays" d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"></path></svg>
      </button>
      <button type="button" class="theme-toggle accbtn" id="accbtn" aria-label="Account" title="Account and shares" onClick={() => {
        if (sessionName.value) {
          location.href = "/dash";
          return;
        }
        (document.getElementById("accpanel") as HTMLDivElement).showPopover();
      }}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
      </button>
    </header>
  );
}

function currentRoute(): string {
  if (location.search.includes("selfcheck")) return "selfcheck";
  if (location.pathname === "/dash") return "dash";
  if (location.pathname.startsWith("/p/")) return "read";
  return "home";
}

const route = currentRoute();

function Boot(): JSX.Element {
  void refreshMe();
  void view.value; // signals subscribed so visibility re-renders
  return (
    <>
      <Header />
      {route === "selfcheck" && <SelfCheck />}
      {route === "dash" && <DashPage />}
      {route === "read" && <ReadView />}
      {route === "home" && (
        <>
          <Gate />
          <ComposeView />
          <LinkView />
        </>
      )}
    </>
  );
}

const root = document.getElementById("app");
if (!root) throw new Error("missing #app");
root.textContent = "";
render(<Boot />, root);
