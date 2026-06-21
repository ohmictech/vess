<script lang="ts">
  let tag = "";
  let copied = false;

  function handleCopy() {
    // In a real implementation, this would show the wallet's stealth address
    navigator.clipboard.writeText(`vess:+${tag}`);
    copied = true;
    setTimeout(() => copied = false, 2000);
  }
</script>

<div class="w-full max-w-lg mx-auto">
  <h1 class="text-xl md:text-2xl font-bold mb-4 md:mb-6">Receive Vess</h1>

  <div class="bg-[#1c2224] rounded-xl border border-[#2a3033] p-4 md:p-6 space-y-4">
    <div class="text-center py-6 md:py-8">
      <div class="w-36 h-36 md:w-48 md:h-48 mx-auto bg-[#252d30] rounded-xl border-2 border-dashed border-[#323a3e] flex items-center justify-center mb-4">
        <span class="text-gray-600 text-sm">QR Code</span>
      </div>
      <p class="text-sm text-gray-400">Scan to receive payment</p>
    </div>

    <div>
      <label class="block text-sm text-gray-400 mb-1">Your Payment Tag</label>
      <div class="flex gap-2">
        <div class="flex-1 bg-[#252d30] border border-[#323a3e] rounded-lg px-3 py-2 text-[#5fb5d2] font-mono text-sm truncate">
          +{tag || "YOUR_TAG"}
        </div>
        <button on:click={handleCopy} class="px-3 py-2 bg-[#252d30] hover:bg-[#323a3e] rounded-lg text-sm transition-colors shrink-0">
          {copied ? "Copied!" : "Copy"}
        </button>
      </div>
    </div>

    <div class="bg-[#252d30]/50 rounded-lg p-3 md:p-4 text-sm text-gray-400">
      <p class="mb-2 font-medium text-gray-300">How to receive:</p>
      <ol class="list-decimal list-inside space-y-1">
        <li>Share your tag (e.g. +ALICE) with the sender</li>
        <li>The sender prepares a stealth-encrypted payment</li>
        <li>Your node automatically detects and claims it</li>
        <li>Bills appear in your wallet after 1 confirmation</li>
      </ol>
    </div>
  </div>
</div>