import { defineConfig } from "@rspress/core";

// zeropaste documentation - served from GitHub Pages under /zeropaste/
export default defineConfig({
  root: "docs",
  base: "/zeropaste/",
  lang: "en",
  title: "zeropaste",
  description: "zero-knowledge pastes - self-hosted, encrypted in your browser",
  icon: "/favicon.png",
  llms: true, // llms.txt + markdown rendering for AI readers
  markdown: {
    link: {
      checkDeadLinks: true,
    },
  },
  themeConfig: {
    enableNav: true,
    enableAppearanceToggle: true,
    socialLinks: [
      {
        icon: "github",
        mode: "link",
        content: "https://github.com/2TAP2B/zeropaste",
      },
    ],
    footer: {
      message: "made with a single Go binary and no logs",
      copyright: "MIT - zeropaste",
    },
  },
});
