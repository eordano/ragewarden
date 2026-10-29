chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg || msg.target !== 'offscreen-clipboard' || msg.kind !== 'clear') return false;
    const ta = document.getElementById('buffer');
    ta.value = ' ';
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.value = '';
    sendResponse({ ok });
    return false;
});
