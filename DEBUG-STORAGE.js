// DEBUG: Find what's consuming storage
// Run this in popup console (F12)

chrome.storage.local.get(null, (allData) => {
  console.log('=== STORAGE ANALYSIS ===');

  const sizes = [];

  for (const [key, value] of Object.entries(allData)) {
    const size = JSON.stringify(value).length;
    sizes.push({ key, size, sizeKB: (size / 1024).toFixed(2) });
  }

  // Sort by size descending
  sizes.sort((a, b) => b.size - a.size);

  console.log('\n📊 TOP 10 LARGEST ITEMS:');
  sizes.slice(0, 10).forEach((item, i) => {
    console.log(`${i + 1}. ${item.key}: ${item.sizeKB} KB`);

    // Show sample of what's in there
    if (item.size > 100000) {
      const data = allData[item.key];
      console.log(`   Type: ${Array.isArray(data) ? 'Array' : typeof data}`);
      if (Array.isArray(data)) {
        console.log(`   Length: ${data.length}`);
        console.log(`   Sample:`, data[0]);
      }
    }
  });

  console.log('\n📈 SUMMARY:');
  console.log(`Total Keys: ${sizes.length}`);
  console.log(`Total Size: ${(sizes.reduce((sum, s) => sum + s.size, 0) / 1024).toFixed(2)} KB`);

  // Find specifically what's bloated
  console.log('\n🔍 LOOKING FOR BLOAT:');

  if (allData.heraSessions) {
    console.log(`heraSessions: ${allData.heraSessions.length} items`);
    if (allData.heraSessions.length > 0) {
      const sample = allData.heraSessions[0];
      console.log('Sample session size:', JSON.stringify(sample).length, 'bytes');
      console.log('Has responseBody?', !!sample.responseBody);
      if (sample.responseBody) {
        console.log('Response body size:', sample.responseBody.length, 'chars');
      }
    }
  }

  // Check for memory manager cache
  const memManagerKeys = Object.keys(allData).filter(k =>
    k.includes('oauth') || k.includes('Flow') || k.includes('auth')
  );
  console.log('\nMemory manager related keys:', memManagerKeys.length);
  memManagerKeys.forEach(key => {
    console.log(`  ${key}: ${(JSON.stringify(allData[key]).length / 1024).toFixed(2)} KB`);
  });

  // Output full list for inspection
  console.log('\n📋 ALL KEYS:');
  sizes.forEach(item => {
    if (item.size > 10000) { // Show only items > 10KB
      console.log(`${item.key}: ${item.sizeKB} KB`);
    }
  });
});
