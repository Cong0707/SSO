import { useEffect, useRef } from "react";
import capWasmURL from "@cap.js/wasm/browser/cap_wasm_bg.wasm?url";

declare global {
  interface Window {
    CAP_CUSTOM_WASM_URL?: string;
    turnstile?: {
      render: (
        element: HTMLElement,
        options: Record<string, unknown>,
      ) => string;
      remove?: (id: string) => void;
    };
  }
}

export type CaptchaConfig = {
  mode: "none" | "turnstile" | "cap";
  site_key?: string;
  api_endpoint?: string;
};

export function BotProtectionChallenge(props: {
  config: CaptchaConfig;
  locale: string;
  onVerify: (token: string) => void;
  onExpire: () => void;
}) {
  if (props.config.mode === "turnstile" && props.config.site_key) {
    return <Turnstile siteKey={props.config.site_key} {...props} />;
  }
  if (props.config.mode === "cap" && props.config.api_endpoint) {
    return <CapWidget endpoint={props.config.api_endpoint} {...props} />;
  }
  return null;
}

function Turnstile(props: {
  siteKey: string;
  locale: string;
  onVerify: (token: string) => void;
  onExpire: () => void;
}) {
  const host = useRef<HTMLDivElement | null>(null);
  const verifyRef = useRef(props.onVerify);
  const expireRef = useRef(props.onExpire);
  useEffect(() => {
    verifyRef.current = props.onVerify;
    expireRef.current = props.onExpire;
  }, [props.onExpire, props.onVerify]);
  useEffect(() => {
    let widgetId = "";
    const render = () => {
      if (!host.current || !window.turnstile) return;
      host.current.replaceChildren();
      widgetId = window.turnstile.render(host.current, {
        sitekey: props.siteKey,
        language: props.locale,
        callback: (token: string) => verifyRef.current(token),
        "error-callback": () => expireRef.current(),
        "expired-callback": () => expireRef.current(),
      });
    };
    const id = "xem-sso-turnstile";
    const existing = document.getElementById(id) as HTMLScriptElement | null;
    if (window.turnstile) render();
    else if (existing)
      existing.addEventListener("load", render, { once: true });
    else {
      const script = document.createElement("script");
      script.id = id;
      script.src =
        "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
      script.async = true;
      script.defer = true;
      script.addEventListener("load", render, { once: true });
      document.head.appendChild(script);
    }
    return () => {
      if (widgetId) window.turnstile?.remove?.(widgetId);
      existing?.removeEventListener("load", render);
    };
  }, [props.locale, props.siteKey]);
  return <div className="captcha-widget" ref={host} />;
}

function CapWidget(props: {
  endpoint: string;
  locale: string;
  onVerify: (token: string) => void;
  onExpire: () => void;
}) {
  const host = useRef<HTMLDivElement | null>(null);
  const verifyRef = useRef(props.onVerify);
  const expireRef = useRef(props.onExpire);
  useEffect(() => {
    verifyRef.current = props.onVerify;
    expireRef.current = props.onExpire;
  }, [props.onExpire, props.onVerify]);
  useEffect(() => {
    const container = host.current;
    if (!container) return;
    let widget: HTMLElement | null = null;
    let cancelled = false;
    const solved = (event: Event) =>
      verifyRef.current((event as CustomEvent<{ token: string }>).detail.token);
    const reset = () => expireRef.current();
    window.CAP_CUSTOM_WASM_URL = capWasmURL;
    void import("@cap.js/widget").then(() => {
      if (cancelled) return;
      widget = document.createElement("cap-widget");
      widget.setAttribute("data-cap-api-endpoint", props.endpoint);
      widget.setAttribute("data-cap-hidden-field-name", "cap_token");
      widget.setAttribute("data-cap-lang", props.locale);
      widget.addEventListener("solve", solved);
      widget.addEventListener("reset", reset);
      widget.addEventListener("error", reset);
      container.replaceChildren(widget);
    });
    return () => {
      cancelled = true;
      widget?.removeEventListener("solve", solved);
      widget?.removeEventListener("reset", reset);
      widget?.removeEventListener("error", reset);
      widget?.remove();
    };
  }, [props.endpoint, props.locale]);
  return <div className="captcha-widget" ref={host} />;
}
