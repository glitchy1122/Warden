import { invoke } from "@tauri-apps/api/core";

type BlockSource = "custom" | "bloom" | "bypass" | "none";

interface BlockEvent {
  domain: string;
  source: BlockSource;
  at: number;
}

interface EngineStatus {
  protectionEnabled: boolean;
  wfpActive: boolean;
  dnsProxyActive: boolean;
  bloomDomains: number;
  customDomains: number;
  blockedTotal: number;
  allowedTotal: number;
  recentBlocks: BlockEvent[];
  adminRequiredHint: string;
}

interface CustomDomain {
  id: number;
  domain: string;
  createdAt: string;
}

interface LookupResult {
  domain: string;
  blocked: boolean;
  source: BlockSource;
}

const toggleBtn = document.querySelector<HTMLButtonElement>("#toggle-protection")!;
const refreshBtn = document.querySelector<HTMLButtonElement>("#refresh-status")!;
const heroStatus = document.querySelector<HTMLParagraphElement>("#hero-status")!;
const adminHint = document.querySelector<HTMLParagraphElement>("#admin-hint")!;
const statusCore = document.querySelector<HTMLDivElement>("#status-core")!;
const metricBloom = document.querySelector<HTMLParagraphElement>("#metric-bloom")!;
const metricCustom = document.querySelector<HTMLParagraphElement>("#metric-custom")!;
const metricBlocked = document.querySelector<HTMLParagraphElement>("#metric-blocked")!;
const metricAllowed = document.querySelector<HTMLParagraphElement>("#metric-allowed")!;
const flagWfp = document.querySelector<HTMLSpanElement>("#flag-wfp")!;
const flagDns = document.querySelector<HTMLSpanElement>("#flag-dns")!;
const customList = document.querySelector<HTMLDivElement>("#custom-list")!;
const recentList = document.querySelector<HTMLDivElement>("#recent-list")!;
const addForm = document.querySelector<HTMLFormElement>("#add-domain-form")!;
const domainInput = document.querySelector<HTMLInputElement>("#domain-input")!;
const formMessage = document.querySelector<HTMLParagraphElement>("#form-message")!;
const checkForm = document.querySelector<HTMLFormElement>("#check-form")!;
const checkInput = document.querySelector<HTMLInputElement>("#check-input")!;
const checkResult = document.querySelector<HTMLParagraphElement>("#check-result")!;

let busy = false;

function formatCount(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

function sourceLabel(source: BlockSource): string {
  switch (source) {
    case "custom":
      return "Custom";
    case "bloom":
      return "Bloom";
    case "bypass":
      return "Finance bypass";
    case "none":
      return "Allowed";
    default: {
      const _exhaustive: never = source;
      return _exhaustive;
    }
  }
}

function setMessage(
  el: HTMLParagraphElement,
  text: string,
  kind: "ok" | "error" | "" = "",
): void {
  el.textContent = text;
  el.classList.toggle("ok", kind === "ok");
  el.classList.toggle("error", kind === "error");
}

function renderStatus(status: EngineStatus): void {
  const on = status.protectionEnabled;
  heroStatus.textContent = on
    ? "Protection is armed — Bloom DNS via 1.1.1.1 / 8.8.8.8"
    : "Protection is offline";
  adminHint.textContent = status.adminRequiredHint;

  toggleBtn.textContent = on ? "Disable protection" : "Enable protection";
  toggleBtn.classList.toggle("is-on", on);
  statusCore.classList.toggle("is-on", on);

  metricBloom.textContent = formatCount(status.bloomDomains);
  metricCustom.textContent = formatCount(status.customDomains);
  metricBlocked.textContent = formatCount(status.blockedTotal);
  metricAllowed.textContent = formatCount(status.allowedTotal);

  flagWfp.textContent = "WFP off (stable)";
  flagWfp.classList.remove("on");
  flagDns.textContent = status.dnsProxyActive ? "DNS → 1.1.1.1 / 8.8.8.8" : "DNS proxy idle";
  flagDns.classList.toggle("on", status.dnsProxyActive);

  if (status.recentBlocks.length === 0) {
    recentList.innerHTML = `<p class="empty">No blocks yet. Enable protection and browse.</p>`;
  } else {
    recentList.replaceChildren(
      ...status.recentBlocks.map((event) => {
        const row = document.createElement("div");
        row.className = "recent-row";
        row.innerHTML = `<div><strong>${escapeHtml(event.domain)}</strong></div><span>${escapeHtml(sourceLabel(event.source))}</span>`;
        return row;
      }),
    );
  }
}

function renderCustom(domains: CustomDomain[]): void {
  if (domains.length === 0) {
    customList.innerHTML = `<p class="empty">No custom domains yet.</p>`;
    return;
  }

  customList.replaceChildren(
    ...domains.map((entry) => {
      const row = document.createElement("div");
      row.className = "domain-row";

      const meta = document.createElement("div");
      meta.innerHTML = `<strong>${escapeHtml(entry.domain)}</strong><br /><span>${escapeHtml(entry.createdAt)}</span>`;

      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "domain-remove";
      remove.textContent = "Remove";
      remove.addEventListener("click", () => {
        void removeDomain(entry.id);
      });

      row.append(meta, remove);
      return row;
    }),
  );
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function refreshAll(): Promise<void> {
  const [status, customs] = await Promise.all([
    invoke<EngineStatus>("get_status"),
    invoke<CustomDomain[]>("list_custom_domains"),
  ]);
  renderStatus(status);
  renderCustom(customs);
}

async function toggleProtection(): Promise<void> {
  if (busy) return;
  busy = true;
  toggleBtn.disabled = true;
  try {
    const current = await invoke<EngineStatus>("get_status");
    const status = await invoke<EngineStatus>("set_protection", {
      enabled: !current.protectionEnabled,
    });
    renderStatus(status);
    setMessage(formMessage, "", "");
  } catch (error) {
    setMessage(formMessage, String(error), "error");
  } finally {
    busy = false;
    toggleBtn.disabled = false;
  }
}

async function addDomain(domain: string): Promise<void> {
  try {
    await invoke("add_custom_domain", { domain });
    domainInput.value = "";
    setMessage(formMessage, `Added ${domain}`, "ok");
    await refreshAll();
  } catch (error) {
    setMessage(formMessage, String(error), "error");
  }
}

async function removeDomain(id: number): Promise<void> {
  try {
    await invoke("remove_custom_domain", { id });
    setMessage(formMessage, "Domain removed", "ok");
    await refreshAll();
  } catch (error) {
    setMessage(formMessage, String(error), "error");
  }
}

async function checkDomain(domain: string): Promise<void> {
  try {
    const result = await invoke<LookupResult>("check_domain", { domain });
    if (result.blocked) {
      setMessage(
        checkResult,
        `${result.domain} is blocked (${sourceLabel(result.source)})`,
        "ok",
      );
    } else if (result.source === "bypass") {
      setMessage(
        checkResult,
        `${result.domain} bypasses Warden (banking/payments/crypto)`,
        "ok",
      );
    } else {
      setMessage(checkResult, `${result.domain} is not blocked`, "");
    }
  } catch (error) {
    setMessage(checkResult, String(error), "error");
  }
}

function bindEvents(): void {
  toggleBtn.addEventListener("click", () => {
    void toggleProtection();
  });
  refreshBtn.addEventListener("click", () => {
    void refreshAll().catch((error) => setMessage(formMessage, String(error), "error"));
  });
  addForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const value = domainInput.value.trim();
    if (!value) return;
    void addDomain(value);
  });
  checkForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const value = checkInput.value.trim();
    if (!value) return;
    void checkDomain(value);
  });
}

async function boot(): Promise<void> {
  bindEvents();
  await refreshAll();
  window.setInterval(() => {
    void invoke<EngineStatus>("get_status")
      .then(renderStatus)
      .catch(() => undefined);
  }, 2000);
}

void boot().catch((error) => {
  setMessage(formMessage, String(error), "error");
});
