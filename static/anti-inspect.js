(function () {
  // Disable right-click
  document.addEventListener("contextmenu", e => e.preventDefault(), false);

  // Define blocked shortcuts
  const blockedCtrlKeys = new Set(["U", "S", "P", "A", "C", "X", "V"]);
  const blockedCtrlShiftKeys = new Set(["I", "J", "C"]);

  document.addEventListener("keydown", e => {
    const key = e.key.toUpperCase();

    // Block F12
    if (key === "F12") {
      e.preventDefault();
      return;
    }

    // Block Ctrl + key
    if (e.ctrlKey && !e.shiftKey && blockedCtrlKeys.has(key)) {
      e.preventDefault();
      return;
    }

    // Block Ctrl + Shift + key
    if (e.ctrlKey && e.shiftKey && blockedCtrlShiftKeys.has(key)) {
      e.preventDefault();
      return;
    }
  }, false);
})();
