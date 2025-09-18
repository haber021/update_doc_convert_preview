// Global Loading Overlay Utility
// Usage:
//   startLoading('Message...')
//   updateLoading('New message')
//   stopLoading()
// Supports nested calls via an internal counter.

(function(){
  let counter = 0;
  const overlayId = 'globalLoadingOverlay';
  const textId = 'globalLoadingText';
  const progressId = 'globalLoadingProgress';

  function getEl(id){ return document.getElementById(id); }
  function show(text){
    const overlay = getEl(overlayId);
    const label = getEl(textId);
    if (!overlay) return;
    if (label && typeof text === 'string') label.textContent = text;
    overlay.classList.remove('d-none');
    overlay.ariaHidden = 'false';
  }
  function hide(){
    const overlay = getEl(overlayId);
    if (!overlay) return;
    overlay.classList.add('d-none');
    overlay.ariaHidden = 'true';
  }

  function start(text){
    counter++;
    show(text || 'Working...');
  }
  function update(text){
    const label = getEl(textId);
    if (label && typeof text === 'string') label.textContent = text;
  }
  function stop(){
    counter = Math.max(0, counter - 1);
    if (counter === 0) hide();
  }

  // Optional: simple progress API (0-100)
  function setProgress(percent){
    const bar = getEl(progressId);
    if (!bar) return;
    const p = Math.max(0, Math.min(100, Number(percent)||0));
    bar.style.width = p + '%';
    bar.setAttribute('aria-valuenow', String(p));
    if (p >= 100) {
      setTimeout(() => { bar.style.width = '0%'; }, 500);
    }
  }

  // Expose globally
  window.startLoading = start;
  window.updateLoading = update;
  window.stopLoading = stop;
  window.setLoadingProgress = setProgress;
})();
