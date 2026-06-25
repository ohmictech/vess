<script lang="ts">
  import { mintTimelock } from "../rpc/client";

  export let asset: "vess" | "bitcoin" | "vichor" = "vess";

  let amountSats: number | null = null;
  let durationYears = 1;
  let vichorBurned = 0;
  let minting = false;
  let result = "";
  let error = "";

  $: assetColor = asset === "vess" ? "#88cddf" : asset === "vichor" ? "#ccff00" : "#f28e13";
  $: inputClass = "w-full rounded-lg px-3 py-2 text-[#1a1a1a] placeholder-[#3d484c] focus:outline-none transition-colors";
  $: inputStyle = `background: ${assetColor}18`;

  // Quadratic Vichor formula: (y-1)² × 10
  $: vichorRequired = durationYears <= 1 ? 0 : Math.round(Math.pow(durationYears - 1, 2) * 10);
  $: vichorDeficit = Math.max(0, vichorRequired - vichorBurned);
  $: canMint = amountSats !== null && amountSats > 0 && vichorDeficit === 0;
  $: vessAmount = amountSats !== null && amountSats !== 0
    ? Math.floor(amountSats * durationYears * 52560 / 52560)
    : 0;

  async function handleMint() {
    if (!amountSats || !canMint) return;
    minting = true;
    error = "";
    result = "";
    try {
      const txid = await mintTimelock(amountSats, durationYears, vichorBurned);
      result = `Time-lock created! TXID: ${txid.slice(0, 32)}...`;
    } catch (e) {
      error = String(e);
    } finally {
      minting = false;
    }
  }
</script>

<div class="w-full max-w-lg mx-auto">
  <h1 class="text-2xl font-bold mb-6">Time-Lock Mint</h1>

  <div class="bg-[#1c2224] rounded-xl border border-[#2a3033] p-6 space-y-4">
    <p class="text-sm text-gray-400">Lock BTC via CLTV and receive Vess time-credits. Your BTC returns after the lock expires.</p>

    <div>
      <label class="block text-sm text-gray-400 mb-1">Amount (satoshis)</label>
      <input
        type="number"
        bind:value={amountSats}
        min="1"
        step="1"
        on:input={() => { if (amountSats !== null) amountSats = Math.floor(amountSats); }}
        class={inputClass}
        style={inputStyle}
      />
    </div>

    <div>
      <label class="block text-sm text-gray-400 mb-1">Duration: {durationYears} year{durationYears === 1 ? '' : 's'}</label>
      <input
        type="range"
        bind:value={durationYears}
        min="0.1"
        max="10"
        step="0.1"
        class="w-full accent-[#88cddf]"
      />
      <div class="flex justify-between text-xs text-gray-600 mt-1">
        <span>0.1 yr</span>
        <span>10 yr</span>
      </div>
    </div>

    <div class="bg-[#252d30] rounded-lg p-4 space-y-2 text-sm">
      <div class="flex justify-between">
        <span class="text-gray-400">Vichor Required</span>
        <span class:text-[#88cddf]={vichorRequired > 0} class:text-gray-500={vichorRequired === 0}>
          {vichorRequired}
        </span>
      </div>
      {#if vichorRequired > 0}
        <div>
          <label class="block text-gray-400 mb-1">Vichor Burned</label>
          <input
            type="number"
            bind:value={vichorBurned}
            min="0"
            max={vichorRequired}
            step="1"
            on:input={() => { vichorBurned = Math.floor(vichorBurned); }}
            class={inputClass + " text-sm"}
            style={inputStyle}
          />
          {#if vichorDeficit > 0}
            <p class="text-red-400 text-xs mt-1">Need {vichorDeficit} more Vichor</p>
          {/if}
        </div>
      {/if}
      <div class="flex justify-between pt-2 border-t border-[#323a3e]">
        <span class="text-gray-400">Vess to Mint</span>
        <span class="text-[#88cddf] font-semibold">~{vessAmount}</span>
      </div>
    </div>

    <button
      on:click={handleMint}
      disabled={minting || !canMint}
      class="w-full py-3 rounded-lg font-semibold transition-colors disabled:opacity-50"
      class:bg-[#88cddf]:hover:bg-[#6bb8c9]:text-black={!minting}
      class:bg-[#323a3e]:text-gray-400={minting}
    >
      {minting ? "Creating Time-Lock..." : "Create Time-Lock"}
    </button>

    {#if result}
      <div class="bg-green-900/20 border border-green-800 rounded-lg p-3 text-green-400 text-sm">{result}</div>
    {/if}
    {#if error}
      <div class="bg-red-900/20 border border-red-800 rounded-lg p-3 text-red-400 text-sm">{error}</div>
    {/if}
  </div>
</div>