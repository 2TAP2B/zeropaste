/// <reference path="./globals.d.ts" />
declare global {
  interface Window {
    hljs?: {
      highlightElement(el: HTMLElement): void;
    };
  }
  var hljs: {
    highlightElement(el: HTMLElement): void;
  } | undefined;
}

export {};
