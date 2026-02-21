const { app, BrowserWindow, dialog, shell, session, ipcMain, clipboard } = require("electron");
const path = require("node:path");
const fs = require("node:fs");
const http = require("node:http");
const { spawn, spawnSync } = require("node:child_process");
const getPort = require("get-port").default; // get-port v7 is ESM (default export)

// Clipboard bridge for renderer (works even when navigator.clipboard is blocked)
try {
  ipcMain.handle("clipboard-write", (_evt, text) => {
    clipboard.writeText(String(text ?? ""));
    return true;
  });
} catch {
  /* ignore */
}

const os = require("node:os");
const crypto = require("node:crypto");

let backend = null;
let backendPort = null;
let shutdownToken = crypto.randomBytes(24).toString("hex");
let guardianToken = crypto.randomBytes(32).toString("hex");
let hmacSecret = crypto.randomBytes(32).toString("hex");
let guardianHeaderPort = null;
let tmpRoot = null;

let isQuitting = false;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function isPidAlive(pid) {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function killProcessTree(pid) {
  if (!pid) return;

  if (process.platform === "win32") {
    try {
      // /T = kill child processes too, /F = force
      spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"], { windowsHide: true });
    } catch {
      /* ignore */
    }
    return;
  }

  // Non-Windows: try process-group kill first (works when spawned detached)
  try {
    process.kill(-pid, "SIGKILL");
    return;
  } catch {
    /* ignore */
  }

  try {
    process.kill(pid, "SIGKILL");
  } catch {
    /* ignore */
  }
}

function waitExit(proc, ms) {
  if (!proc) return Promise.resolve();
  return new Promise((resolve) => {
    let done = false;
    const t = setTimeout(() => {
      if (done) return;
      done = true;
      resolve();
    }, ms);

    proc.once("exit", () => {
      if (done) return;
      done = true;
      clearTimeout(t);
      resolve();
    });
  });
}

async function shutdownApp() {
  if (isQuitting) return;
  isQuitting = true;

  try {
    await stopBackend();
  } catch {
    /* ignore */
  }

  try {
    if (tmpRoot) {
      rmrf(tmpRoot);
      tmpRoot = null;
    }
  } catch {
    /* ignore */
  }

  try {
    app.exit(0);
  } catch {
    try {
      app.quit();
    } catch {
      /* ignore */
    }
  }
}

app.on("web-contents-created", (_event, contents) => {
  // Disable <webview>
  contents.on("will-attach-webview", (event) => {
    event.preventDefault();
  });

  // Deny permission requests
  contents.session.setPermissionRequestHandler((_wc, _permission, callback) => {
    callback(false);
  });

  function isSafeExternalUrl(raw) {
    try {
      const u = new URL(raw);
      // Only allow https and mailto externally (block file:, javascript:, data:, etc.)
      if (u.protocol === "https:") return true;
      if (u.protocol === "mailto:") return true;
      return false;
    } catch {
      return false;
    }
  }

  // Keep navigation inside the app on localhost only
  contents.on("will-navigate", (event, url) => {
    try {
      const u = new URL(url);
      const okProto = u.protocol === "http:" || u.protocol === "https:";
      const okHost = u.hostname === "127.0.0.1" || u.hostname === "localhost";
      if (!okProto || !okHost) event.preventDefault();
    } catch {
      event.preventDefault();
    }
  });

  // Block popups; allow only localhost. External opens are restricted to safe schemes.
  contents.setWindowOpenHandler(({ url }) => {
    try {
      const u = new URL(url);
      const okHost = u.hostname === "127.0.0.1" || u.hostname === "localhost";
      if (okHost) return { action: "allow" };
      if (isSafeExternalUrl(url)) {
        shell.openExternal(url).catch(() => {
          /* ignore */
        });
      }
      return { action: "deny" };
    } catch {
      return { action: "deny" };
    }
  });
});

function rmrf(p) {
  try {
    if (fs.existsSync(p)) {
      fs.rmSync(p, { recursive: true, force: true });
    }
  } catch {
    /* ignore */
  }
}

function ensureTmpRoot() {
  if (tmpRoot) return tmpRoot;
  const base = os.tmpdir();
  const name = `wizard-${crypto.randomBytes(8).toString("hex")}`;
  tmpRoot = path.join(base, name);
  fs.mkdirSync(tmpRoot, { recursive: true });
  return tmpRoot;
}

/**
 * Add a per-run token header for requests to the local backend.
 */
function installAuthHeaders(port) {
  if (!port) return;
  if (guardianHeaderPort === port) return;
  guardianHeaderPort = port;

  try {
    const filter = { urls: [`http://127.0.0.1:${port}/*`] };

    session.defaultSession.webRequest.onBeforeSendHeaders(filter, (details, callback) => {
      const headers = details.requestHeaders || {};

      // Zero-trust: every backend request must be attested and signed.
      const ts = Math.floor(Date.now() / 1000).toString();
      const nonce = crypto.randomBytes(12).toString("hex");

      try {
        const u = new URL(details.url);
        let p = u.pathname;
        try { p = decodeURIComponent(p); } catch { /* ignore */ }
        const payload = `${details.method}\n${p}${u.search}\n${ts}\n${nonce}\n${guardianToken}`;
        const sig = crypto.createHmac("sha256", hmacSecret).update(payload).digest("hex");

        headers["X-Wizard-Token"] = guardianToken;
        headers["X-Wizard-TS"] = ts;
        headers["X-Wizard-Nonce"] = nonce;
        headers["X-Wizard-Signature"] = sig;
        headers["X-Requested-With"] = "who-wizard";
      } catch {
        // If we can't sign, fail closed on the backend.
        headers["X-Wizard-Token"] = guardianToken;
      }

      callback({ requestHeaders: headers });
    });
  } catch {
    /* ignore */
  }
}

// Back-compat alias
const installGuardianHeader = installAuthHeaders;

function existsOrThrow(p, label) {
  if (!fs.existsSync(p)) {
    throw new Error(`${label} not found: ${p}`);
  }
  return p;
}

/**
 * BrowserWindow icon for dev runs (installer icon is set by electron-builder).
 */
function getIconPath() {
  if (app.isPackaged) return undefined;

  const baseDir = path.join(__dirname, "resources");

  if (process.platform === "win32") {
    const icoCandidates = ["who-emblem.ico", "who-wizard.ico"];
    for (const name of icoCandidates) {
      const p = path.join(baseDir, "icons", name);
      if (fs.existsSync(p)) return p;
    }
  }

  const pngCandidates = ["who-emblem.png", "who-wizard.png"];
  for (const name of pngCandidates) {
    const p = path.join(baseDir, "icons", name);
    if (fs.existsSync(p)) return p;
  }

  return undefined;
}

/**
 * STRICT bundled tools env (no system tools).
 */
function buildStrictToolsEnv(resourcesBase) {
  const binRoot = path.join(resourcesBase, "bin");
  const gitRoot = path.join(binRoot, "git");
  const gpgRoot = path.join(binRoot, "gnupg");
  const pythonHome = path.join(resourcesBase, "python");

  const gitCmdDir = path.join(gitRoot, "cmd");
  const gitBinDir = path.join(gitRoot, "bin");
  const gitMingwDir = path.join(gitRoot, "mingw64", "bin");
  const gitUsrBinDir = path.join(gitRoot, "usr", "bin");

  const gpgBinDir = path.join(gpgRoot, "bin");

  // Prefer cmd\git.exe (canonical). If missing, fallback to bin\git.exe.
  const gitExeWin = fs.existsSync(path.join(gitCmdDir, "git.exe"))
    ? path.join(gitCmdDir, "git.exe")
    : path.join(gitBinDir, "git.exe");

  const pythonExe =
    process.platform === "win32"
      ? path.join(pythonHome, "python.exe")
      : path.join(pythonHome, "bin", "python3");

  const gpgExe = process.platform === "win32" ? path.join(gpgBinDir, "gpg.exe") : path.join(gpgBinDir, "gpg");
  const gpgconfExe =
    process.platform === "win32" ? path.join(gpgBinDir, "gpgconf.exe") : path.join(gpgBinDir, "gpgconf");

  // Validate shipped tools exist (STRICT mode)
  if (process.platform === "win32") {
    existsOrThrow(gitExeWin, "Bundled Git (git.exe)");
    existsOrThrow(gpgExe, "Bundled GnuPG (gpg.exe)");
    existsOrThrow(gpgconfExe, "Bundled GnuPG (gpgconf.exe)");
    existsOrThrow(pythonExe, "Bundled Python (python.exe)");
  }

  // Dedicated GPG home (never mix with system)
  const appData = app.getPath("appData");
  const gpgHome = path.join(appData, "wizard_gpg", "gnupg");
  try {
    fs.mkdirSync(gpgHome, { recursive: true });
  } catch {
    /* ignore */
  }

  // Strict PATH: ONLY bundled dirs + Windows essentials
  const systemRoot = process.env.SystemRoot || String.raw`C:\Windows`;
  const system32 = path.join(systemRoot, "System32");

  const strictPath = [
    gitCmdDir,
    gitBinDir,
    gitMingwDir,
    gitUsrBinDir,
    gpgBinDir,
    pythonHome,
    system32,
    systemRoot
  ]
    .filter(Boolean)
    .join(path.delimiter);

  return {
    gitRoot,
    gitCmdDir,
    gitBinDir,
    gitMingwDir,
    gitUsrBinDir,
    gpgRoot,
    gpgBinDir,
    pythonHome,
    pythonExe,
    gitExe: process.platform === "win32" ? gitExeWin : path.join(gitBinDir, "git"),
    gpgExe,
    gpgconfExe,
    gpgHome,
    strictPath
  };
}

/**
 * Resolve backend command/env for packaged vs dev.
 */
function getBackendCommand() {
  const isPackaged = app.isPackaged;
  const resourcesBase = isPackaged ? process.resourcesPath : path.join(__dirname, "resources");

  const tools = buildStrictToolsEnv(resourcesBase);

  const baseEnv = {
    ...process.env,

    // Force bundled-tools-only behavior in backend.
    WIZARD_TOOLS_STRICT: "1",
    WIZARD_TOOLS_ROOT: path.join(resourcesBase, "bin"),

    PYTHONPATH: "",

    // Portable tool roots
    WIZARD_GIT_ROOT: tools.gitRoot,
    WIZARD_GIT_CMD_DIR: tools.gitCmdDir,
    WIZARD_GIT_BIN_DIR: tools.gitBinDir,
    WIZARD_GIT_MINGW_DIR: tools.gitMingwDir,
    WIZARD_GIT_USR_BIN_DIR: tools.gitUsrBinDir,

    WIZARD_GPG_ROOT: tools.gpgRoot,
    WIZARD_GPG_BIN: tools.gpgBinDir,

    // Absolute binaries (backend must use these, never system)
    GIT_BINARY: tools.gitExe,
    GPG_BINARY: tools.gpgExe,
    GPGCONF_BINARY: tools.gpgconfExe,
    WIZARD_PYTHON: tools.pythonExe,

    // Backward-compat envs some modules may read
    WIZARD_GIT_EXE: tools.gitExe,
    WIZARD_GPG_EXE: tools.gpgExe,

    // Dedicated GPG home
    GNUPGHOME: tools.gpgHome,

    // Strict PATH (no system git/gpg/python)
    PATH: tools.strictPath,

    SHUTDOWN_TOKEN: shutdownToken,
    WIZARD_SHUTDOWN_TOKEN: shutdownToken,

    WIZARD_GUARDIAN_TOKEN: guardianToken,
    GUARDIAN_TOKEN: guardianToken,

    // Per-run HMAC secret for request signing (backend verifies; never exposed to renderer).
    WIZARD_HMAC_SECRET: hmacSecret
  };

  if (isPackaged) {
    const exePath = path.join(process.resourcesPath, "backend", "wizard-backend", "wizard-backend.exe");
    if (fs.existsSync(exePath)) {
      return { cmd: exePath, args: [], env: baseEnv, runType: "exe" };
    }

    const legacyExe = path.join(process.resourcesPath, "bin", "wizard-backend.exe");
    if (fs.existsSync(legacyExe)) {
      return { cmd: legacyExe, args: [], env: baseEnv, runType: "exe" };
    }

    const pyEntrypoint1 = path.join(process.resourcesPath, "backend", "wizard-backend", "wizard-backend.py");
    const pyEntrypoint2 = path.join(process.resourcesPath, "bin", "wizard-backend.py");

    if (fs.existsSync(pyEntrypoint1)) {
      existsOrThrow(tools.pythonExe, "Packaged Python executable");
      return {
        cmd: tools.pythonExe,
        args: [pyEntrypoint1],
        env: { ...baseEnv, PYTHONHOME: tools.pythonHome },
        runType: "py"
      };
    }

    if (fs.existsSync(pyEntrypoint2)) {
      existsOrThrow(tools.pythonExe, "Packaged Python executable");
      return {
        cmd: tools.pythonExe,
        args: [pyEntrypoint2],
        env: { ...baseEnv, PYTHONHOME: tools.pythonHome },
        runType: "py"
      };
    }

    throw new Error(
      "Packaged backend not found. Expected one of:\n" +
      `- ${exePath}\n` +
      `- ${legacyExe}\n` +
      `- ${pyEntrypoint1}\n` +
      `- ${pyEntrypoint2}`
    );
  }

  const devBackend1 = path.join(__dirname, "backend", "server.py");
  const devBackend2 = path.join(__dirname, "wizard-backend", "wizard-backend.py");

  const devBackend = fs.existsSync(devBackend1) ? devBackend1 : devBackend2;
  existsOrThrow(devBackend, "Dev backend entrypoint");
  existsOrThrow(tools.pythonExe, "Dev Python executable (resources/python)");

  return {
    cmd: tools.pythonExe,
    args: [devBackend],
    env: { ...baseEnv, PYTHONHOME: tools.pythonHome },
    runType: "py"
  };
}

/**
 * Wait until backend /healthz responds.
 */
function waitForHealth(port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const start = Date.now();

    function attempt() {
      const req = http.get(
        {
          hostname: "127.0.0.1",
          port,
          path: "/healthz",
          timeout: 3000
        },
        (res) => {
          res.resume();
          if (res.statusCode === 200) return resolve(true);
          retry();
        }
      );

      req.on("error", retry);
      req.on("timeout", () => {
        req.destroy();
        retry();
      });
    }

    function retry() {
      if (Date.now() - start > timeoutMs) {
        return reject(new Error("Backend health check timed out"));
      }
      setTimeout(attempt, 500);
    }

    attempt();
  });
}

/**
 * Start backend on a free port.
 */
async function startBackend() {
  if (backend && backendPort) return;

  const tmp = ensureTmpRoot();
  const logFile = path.join(tmp, "wizard-backend.log");
  const logStream = fs.createWriteStream(logFile, { flags: "a" });

  backendPort = await getPort();

  const { cmd, args, env, runType } = getBackendCommand();

  if (runType === "exe") {
    existsOrThrow(cmd, "Backend EXE");
  }

  const finalEnv = {
    ...env,
    HOST: "127.0.0.1",
    PORT: String(backendPort),
    WIZARD_PORT: String(backendPort),
    TMPDIR: tmp,
    TEMP: tmp,
    TMP: tmp
  };

  const spawnCwd = app.isPackaged ? path.dirname(cmd) : tmp;

  backend = spawn(cmd, args, {
    env: finalEnv,
    cwd: spawnCwd,
    windowsHide: true,
    detached: process.platform !== "win32"
  });

  backend.stdout?.on("data", (data) => {
    logStream.write(`[backend stdout] ${data}`);
  });

  backend.stderr?.on("data", (data) => {
    logStream.write(`[backend stderr] ${data}`);
  });

  backend.on("exit", (code, signal) => {
    logStream.write(`[backend exit] code=${code} signal=${signal}\n`);
  });

  await waitForHealth(backendPort, 60_000);
}

/**
 * POST shutdown request to backend.
 */
function requestShutdown(pathname, headers = {}) {
  return new Promise((resolve) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: backendPort,
        path: pathname,
        method: "POST",
        timeout: 3000,
        headers
      },
      (res) => {
        res.resume();
        resolve(res.statusCode && res.statusCode < 500);
      }
    );

    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });

    req.end();
  });
}

/**
 * Best-effort backend shutdown.
 */
async function stopBackend() {
  if (!backend) return;

  const proc = backend;
  const pid = proc.pid;
  const port = backendPort;

  // Try graceful shutdown via HTTP (best effort)
  if (port) {
    try {
      let ok = await requestShutdown("/__shutdown__", { "X-Auth": shutdownToken });

      if (!ok) ok = await requestShutdown("/__control/shutdown", { "X-Auth": shutdownToken });

      if (!ok) await requestShutdown("/shutdown", { "X-Shutdown-Token": shutdownToken });
    } catch {
      /* ignore */
    }
  }

  // Ask process to terminate
  try {
    proc.kill();
  } catch {
    /* ignore */
  }

  // Wait a bit for clean exit
  await waitExit(proc, 2000);

  // If still alive, force-kill entire tree
  if (pid && isPidAlive(pid)) {
    killProcessTree(pid);
    await sleep(300);
  }

  backend = null;
  backendPort = null;

  shutdownToken = crypto.randomBytes(24).toString("hex");
  guardianToken = crypto.randomBytes(32).toString("hex");
  hmacSecret = crypto.randomBytes(32).toString("hex");
  guardianHeaderPort = null;
}

/**
 * Main window.
 */
async function createWindow() {
  await startBackend();
  installGuardianHeader(backendPort);

  const win = new BrowserWindow({
    width: 1280,
    height: 900,
    icon: getIconPath(),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      nodeIntegrationInSubFrames: false,
      sandbox: true,
      webviewTag: false,
      enableRemoteModule: false,
      safeDialogs: true,
      spellcheck: false,
      webSecurity: true,
      devTools: !app.isPackaged
    }
  });

  win.on("close", (e) => {
    if (isQuitting) return;
    e.preventDefault();
    shutdownApp().catch(() => {
      /* ignore */
    });
  });

  await win.loadURL(`http://127.0.0.1:${backendPort}/`);
}

process.on("uncaughtException", (err) => {
  dialog.showErrorBox("WHO Onboarding Wizard", String(err && (err.stack || err.message || err)));
  try {
    app.quit();
  } catch {
    /* ignore */
  }
});

// ✅ Correct CommonJS (no top-level await) — paste this whole block and REMOVE your current try/await part

app.whenReady().then(async () => { // NOSONAR javascript:S7785
  session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => {
    callback(false);
  });

  try {
    await createWindow();
  } catch (err) {
    dialog.showErrorBox(
      "WHO Onboarding Wizard",
      `Failed to start application.\n\n${String(err?.stack || err?.message || err)}`
    );
    app.quit();
  }

  // keep other startup code here (ipc, etc.) if needed
});

app.on("activate", async () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    try {
      await createWindow();
    } catch {
      /* ignore */
    }
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    shutdownApp().catch(() => {
      /* ignore */
    });
    return;
  }

  // macOS: closing last window does not quit the app by default
  stopBackend().catch(() => {
    /* ignore */
  });
  try {
    if (tmpRoot) {
      rmrf(tmpRoot);
      tmpRoot = null;
    }
  } catch {
    /* ignore */
  }
});

app.on("before-quit", (e) => {
  if (isQuitting) return;
  e.preventDefault();
  shutdownApp().catch(() => {
    /* ignore */
  });
});

process.on("exit", () => {
  try {
    if (backend) backend.kill();
  } catch {
    /* ignore */
  }
});