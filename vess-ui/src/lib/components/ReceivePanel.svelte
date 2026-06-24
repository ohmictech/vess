<script lang="ts">
  export let asset: "vess" | "bitcoin" | "vichor" = "vess";

  let tag = "";
  let requestedAmount: number | null = null;
  let copied = false;

  $: assetColor = asset === "vess" ? "#5fb5d2" : asset === "vichor" ? "#ccff00" : "#f28e13";
  $: accentStyle = `background: ${assetColor}18; color: ${assetColor}`;
  $: inputClass = "w-full rounded-lg px-3 py-2 text-[#1a1a1a] placeholder-[#3d484c] focus:outline-none transition-colors";
  $: inputStyle = `background: ${assetColor}18`;
  $: assetLabel = asset === "vess" ? "Vess" : "Vichor";

  function handleCopy() {
    navigator.clipboard.writeText(`+${tag || "ALICE"}`);
    copied = true;
    setTimeout(() => copied = false, 2000);
  }
</script>

<div class="space-y-4">
  <h1 class="text-xl font-bold" style="color: {assetColor}">Receive {assetLabel}</h1>

  <div>
    <label class="block text-sm text-gray-400 mb-1">Your Tag</label>
    <div class="flex gap-2">
      <div class="flex-1 rounded-lg px-3 py-2 font-mono text-sm truncate tag-case" style={accentStyle}>
        +{tag || "ALICE"}
      </div>
      <button on:click={handleCopy} class="px-3 py-2 bg-[#252d30] hover:bg-[#323a3e] rounded-lg text-sm transition-colors shrink-0">
        {copied ? "Copied!" : "Copy"}
      </button>
    </div>
  </div>

  <div>
    <label class="block text-sm text-gray-400 mb-1">Requested Amount ({assetLabel})</label>
    <input
      type="number"
      bind:value={requestedAmount}
      min="1"
      step="1"
      placeholder="0"
      on:input={() => { if (requestedAmount !== null) requestedAmount = Math.floor(requestedAmount); }}
      class={inputClass}
      style={inputStyle}
    />
  </div>

  <div class="bg-[#252d30]/50 rounded-lg p-3 text-sm text-gray-400">
    <p class="mb-1 font-medium text-gray-300">How to receive:</p>
    <ol class="list-decimal list-inside space-y-0.5">
      <li>Share your tag with the sender</li>
      <li>They prepare a stealth-encrypted payment</li>
      <li>Your node detects and claims it automatically</li>
    </ol>
  </div>
</div>