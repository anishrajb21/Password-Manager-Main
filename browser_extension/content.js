(() => {
  if (window.__pmAutofillListenerInstalled) return;
  window.__pmAutofillListenerInstalled = true;
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type !== "PM_FILL" || !message.credential) return;
    try {
      const visible = (el) => !!el && el.getClientRects().length > 0 && !el.disabled && !el.readOnly;
      const inputs = [...document.querySelectorAll("input")].filter(visible);
      const passwordField = inputs.find((el) => el.type.toLowerCase() === "password");
      const usernameField = inputs.find((el) => /^(email|text|tel)$/i.test(el.type) && (/user|email|login|account/i.test(`${el.name} ${el.id} ${el.autocomplete}`) || el.type === "email")) || inputs.find((el) => /^(email|text|tel)$/i.test(el.type) && el !== passwordField);
      if (!passwordField) { sendResponse({ok:false,error:"No visible password field found."}); return; }
      const setNativeValue = (element, value) => {
        const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(element), "value")?.set;
        if (setter) setter.call(element, value); else element.value = value;
        element.dispatchEvent(new Event("input", {bubbles:true})); element.dispatchEvent(new Event("change", {bubbles:true}));
      };
      if (usernameField && message.credential.username) setNativeValue(usernameField, message.credential.username);
      setNativeValue(passwordField, message.credential.password);
      sendResponse({ok:true});
    } catch { sendResponse({ok:false,error:"Autofill failed safely."}); }
  });
})();
