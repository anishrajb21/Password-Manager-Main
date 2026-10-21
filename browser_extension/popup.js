const HOST = "com.local_password_manager.autofill";
let port = null, nextId = 1, pending = new Map(), activeTab = null, activeOrigin = "";
const $ = (id) => document.getElementById(id);
function status(message) { $("status").textContent = message; }
function connect() {
  if (port) return port;
  port = chrome.runtime.connectNative(HOST);
  port.onMessage.addListener((message) => { const p = pending.get(message.id); if (p) { pending.delete(message.id); p(message); } });
  port.onDisconnect.addListener(() => { const error = chrome.runtime.lastError?.message || "Native host disconnected."; for (const [, resolve] of pending) resolve({ok:false,error}); pending.clear(); port = null; $("vault").hidden = true; $("unlock").hidden = false; status(error + " Check native host installation."); });
  return port;
}
function request(action, extra = {}) {
  return new Promise((resolve) => {
    const p = connect(), id = nextId++;
    pending.set(id, resolve);
    p.postMessage({id, action, origin: activeOrigin, ...extra});
    setTimeout(() => { if (pending.has(id)) { pending.delete(id); resolve({ok:false,error:"Native host request timed out."}); } }, 10000);
  });
}
async function init() {
  const tabs = await chrome.tabs.query({active:true,currentWindow:true}); activeTab = tabs[0];
  try { const u = new URL(activeTab.url); activeOrigin = u.origin; $("origin").textContent = `Website: ${activeOrigin}`; }
  catch { $("origin").textContent = "This page cannot receive autofill."; $("unlockButton").disabled = true; }
}
async function findMatches() {
  if (!activeOrigin) return;
  status("Checking saved website matches…");
  const response = await request("site_search");
  if (!response.ok) { status(response.error || "Search failed."); return; }
  const results = $("results"); results.replaceChildren();
  if (!response.credentials.length) { results.textContent = "No credentials saved for this exact hostname."; status("No matching credentials."); return; }
  for (const credential of response.credentials) {
    const card = document.createElement("div"); card.className = "credential";
    const label = document.createElement("div"); label.textContent = `${credential.platform} — ${credential.username}`;
    const button = document.createElement("button"); button.textContent = "Autofill this login";
    button.addEventListener("click", () => fill(credential)); card.append(label, button); results.append(card);
  }
  status(`${response.credentials.length} exact-host match(es).`);
}
async function fill(credential) {
  status("Retrieving selected credential…");
  const response = await request("get", {platform:credential.platform,username:credential.username});
  if (!response.ok) { status(response.error || "Could not retrieve credential."); return; }
  try {
    await chrome.scripting.executeScript({target:{tabId:activeTab.id},files:["content.js"]});
    const result = await chrome.tabs.sendMessage(activeTab.id,{type:"PM_FILL",credential:response.credential});
    status(result?.ok ? "Credential submitted to visible login fields. Review the page before submitting." : (result?.error || "No suitable login fields found."));
  } catch { status("Could not fill this page. Some browser pages block extensions."); }
}
$("unlockButton").addEventListener("click", async () => {
  const password = $("master").value; if (!password) { status("Enter your master password."); return; }
  status("Unlocking local vault…");
  const response = await request("unlock", {master_password:password}); $("master").value = "";
  if (!response.ok) { status(response.error || "Unlock failed."); return; }
  $("unlock").hidden = true; $("vault").hidden = false; status("Vault unlocked for this native-host session."); await findMatches();
});
$("refreshButton").addEventListener("click", findMatches);
$("lockButton").addEventListener("click", async () => { await request("lock"); if (port) port.disconnect(); port = null; $("vault").hidden = true; $("unlock").hidden = false; $("results").replaceChildren(); status("Vault locked."); });
$("openDashboard").addEventListener("click", () => chrome.tabs.create({url: chrome.runtime.getURL("dashboard.html")}));
init();
