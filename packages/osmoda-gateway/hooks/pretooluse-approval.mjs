#!/usr/bin/env node
// PreToolUse approval hook for the tier-0 claude-code agent.
//
// WHY: the default claude-code agent has the native Bash/Write/Edit tools, which
// execute directly and bypass agentd's destructive-command blocklist, the
// ApprovalGate, and the audit ledger — those only sat in front of the structured
// shell_exec/file_write MCP tools. This hook closes that gap: it routes the native
// tools through agentd's `POST /approval/check` (over the Unix socket) so the SAME
// policy + ledger now cover the path the agent actually uses.
//
// CONTRACT: emit a "deny" decision to BLOCK a tool call; stay silent (exit 0) to
// ALLOW. The hook ONLY ever blocks — it never force-approves — so it cannot weaken
// any other permission check. It fails OPEN on malformed input or an unreachable
// agentd for ordinary ops (so an outage doesn't brick the agent), but fails CLOSED
// on a tiny local catastrophic backstop so box-ending commands are blocked even
// when agentd is down. agentd's matcher remains the real, tested policy.

import fs from "node:fs";
import http from "node:http";
import { fileURLToPath } from "node:url";

const GATED_TOOLS = new Set(["Bash", "Write", "Edit", "MultiEdit", "NotebookEdit"]);
const SOCKET = process.env.OSMODA_SOCKET || "/run/osmoda/agentd.sock";

// Paths whose modification could disable the guardrails or leak secrets. Writing
// these via the native tools always needs approval — even though editing ordinary
// system config (e.g. NixOS modules) is a normal, allowed part of the agent's job,
// so we deliberately do NOT blanket-protect /etc or the nix config here.
const SELF_PROTECT = [
  "/var/lib/osmoda/config/credentials",        // the AES-GCM credential store
  "/var/lib/osmoda/config/gateway-token",
  "/var/lib/osmoda/config/claude-settings.json", // this hook's own settings file
  "/authorized_keys",
  "/.ssh/",
  "id_ed25519",
  "id_rsa",
];

// Last-resort denylist used ONLY when agentd is unreachable. Intentionally tiny —
// just irreversible, box-ending commands. Everything else fails open on outage.
const CATASTROPHIC = [
  /\brm\s+-[a-z]*r[a-z]*f?\s+\/(?:\s|$)/i,            // rm -rf /
  /\brm\s+-[a-z]*r[a-z]*f?\s+\/\*/i,                  // rm -rf /*
  /\bmkfs\b/i,
  /\bdd\b[^\n]*\bof=\/dev\//i,                        // dd of=/dev/sdX
  /\b(shutdown|reboot|halt|poweroff)\b/i,
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/,       // fork bomb :(){ :|:& };:
  /\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(ba)?sh\b/i,   // curl … | sh
  />\s*\/dev\/sd[a-z]/i,                              // > /dev/sdX
];

/** Classify a tool call into what we must check. Pure — exported for tests. */
export function gatedKind(toolName, toolInput) {
  if (!GATED_TOOLS.has(toolName)) return { kind: "skip" };
  if (toolName === "Bash") return { kind: "bash", command: String(toolInput?.command ?? "") };
  const path = String(toolInput?.file_path ?? toolInput?.notebook_path ?? "");
  return { kind: "write", path };
}

/** True if writing `path` could disable guardrails or leak secrets. Pure. */
export function isSelfProtected(path) {
  if (!path) return false;
  return SELF_PROTECT.some((p) => path.includes(p));
}

/** Local catastrophic backstop, used only when agentd is unreachable. Pure. */
export function isCatastrophic(command) {
  if (!command) return false;
  return CATASTROPHIC.some((re) => re.test(command));
}

/**
 * True when this file was launched as the process entrypoint (rather than
 * imported by the unit tests). Both sides are resolved through realpath first:
 * the hook is normally installed as a symlink into the agent's settings dir, so
 * a naive `import.meta.url === file://${process.argv[1]}` comparison fails and
 * the gate would silently no-op — i.e. every gated tool call would run ungated.
 */
export function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  if (!import.meta.url.startsWith("file:")) return false;
  try {
    return fs.realpathSync(entry) === fs.realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

function emitDeny(reason) {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: reason,
      },
    }),
  );
  process.exit(0);
}

// Silent exit 0 = proceed (subject to claude's normal permissions). The hook never
// force-approves, so it can't override other safeguards.
function emitAllow() {
  process.exit(0);
}

/** POST the command to agentd's ApprovalGate. Resolves {ok, allow, reason}. */
function checkAgentd(command) {
  return new Promise((resolve) => {
    const body = JSON.stringify({ command });
    const req = http.request(
      {
        socketPath: SOCKET,
        path: "/approval/check",
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
        timeout: 2000,
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try {
            resolve({ ok: true, ...JSON.parse(data) });
          } catch {
            resolve({ ok: false });
          }
        });
      },
    );
    req.on("error", () => resolve({ ok: false }));
    req.on("timeout", () => {
      req.destroy();
      resolve({ ok: false });
    });
    req.write(body);
    req.end();
  });
}

async function main() {
  let input;
  try {
    const raw = await new Promise((resolve) => {
      let s = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (c) => (s += c));
      process.stdin.on("end", () => resolve(s));
    });
    input = JSON.parse(raw);
  } catch {
    emitAllow(); // malformed hook input → don't break the agent
    return;
  }

  const g = gatedKind(input.tool_name, input.tool_input);
  if (g.kind === "skip") {
    emitAllow();
    return;
  }

  if (g.kind === "write") {
    if (isSelfProtected(g.path)) {
      emitDeny(
        `Writing '${g.path}' is guardrail-protected. Have the operator make this change, ` +
          `or request approval first (approval_request → operator approves → retry).`,
      );
    }
    emitAllow();
    return;
  }

  // Bash — the arbitrary-execution path. Defer to agentd's tested matcher.
  const verdict = await checkAgentd(g.command);
  if (verdict.ok) {
    if (verdict.allow) {
      emitAllow();
      return;
    }
    emitDeny(
      verdict.reason ||
        "Blocked by osModa ApprovalGate: this destructive command needs an approved approval_id " +
          "(call approval_request, have the operator approve, then retry).",
    );
    return;
  }

  // agentd unreachable → catastrophic backstop only, else fail open.
  if (isCatastrophic(g.command)) {
    emitDeny(
      "osModa ApprovalGate is unreachable and this matches a catastrophic pattern — blocked. " +
        "Retry once agentd is healthy, or request approval.",
    );
    return;
  }
  emitAllow();
}

// Run only when invoked directly (not when imported by the unit tests).
if (invokedDirectly()) {
  main();
}
