/// <reference path="./globals.d.ts" />
declare global {
  interface Window {
    hljs?: {
      highlightElement(el: HTMLElement): void;
      highlight(code: string, opts: { language: string }): { value: string };
    };
  }
  var hljs: {
    highlightElement(el: HTMLElement): void;
    highlight(code: string, opts: { language: string }): { value: string };
  } | undefined;
}

export {};
