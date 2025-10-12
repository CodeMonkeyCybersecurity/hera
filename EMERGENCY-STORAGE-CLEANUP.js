// EMERGENCY STORAGE CLEANUP SCRIPT
// Run this in the extension popup console (F12 on popup.html)

console.log('🚨 Starting emergency storage cleanup...');

// Step 1: Clear all storage data
chrome.storage.local.clear(() => {
  console.log('✅ Storage cleared');

  // Step 2: Reset memory manager state in background
  chrome.runtime.sendMessage({ action: 'resetMemoryManager' }, (response) => {
    console.log('✅ Memory manager reset:', response);

    // Step 3: Reload popup
    console.log('✅ Cleanup complete. Reloading popup...');
    setTimeout(() => {
      location.reload();
    }, 1000);
  });
});

// Alternative: Clear only old sessions (preserve settings)
/*
chrome.storage.local.get(null, (allData) => {
  const toKeep = {};

  // Keep settings
  if (allData.heraConfig) toKeep.heraConfig = allData.heraConfig;
  if (allData.privacyConsent) toKeep.privacyConsent = allData.privacyConsent;

  // Keep only recent sessions (last 24 hours)
  if (allData.heraSessions) {
    const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
    toKeep.heraSessions = allData.heraSessions
      .filter(s => (s._timestamp || s.timestamp || 0) > oneDayAgo)
      .slice(-50); // Keep max 50
  }

  chrome.storage.local.clear(() => {
    chrome.storage.local.set(toKeep, () => {
      console.log('✅ Selective cleanup complete');
      location.reload();
    });
  });
});
*/
