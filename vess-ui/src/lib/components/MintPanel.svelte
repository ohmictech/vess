<script lang="ts">
  import { mintTimelock } from "../rpc/client";

  export let asset: "vess" | "bitcoin" | "vichor" = "vess";

  let amountSats: number | null = null;
  let durationYears = 1;
  let vichorBurned = 0;
  let centuryLock = false;
  let minting = false;
  let result = "";
  let error = "";

  $: assetColor = asset === "vess" ? "#88cddf" : asset === "vichor" ? "#ccff00" : "#f28e13";
  $: inputClass = "w-full rounded-lg px-3 py-2 text-[#1a1a1a] placeholder-[#3d484c] focus:outline-none transition-colors";
  $: inputStyle = `background: ${assetColor}18`;

  // Century lock forces 100-year duration, no Vichor required.
  $: effectiveYears = centuryLock ? 100 : durationYears;
  $: vichorRequired = centuryLock ? 0 : Math.ceil((amountSats || 0) * durationYears / 100_000);
  $: vichorDeficit = Math.max(0, vichorRequired - vichorBurned);
  $: canMint = amountSats !== null && amountSats > 0 && vichorDeficit === 0;
  $: vessAmount = amountSats !== null && amountSats !== 0
    ? Math.floor(amountSats * effectiveYears * 52560 / 52560)
    : 0;

  // Per-block Vess amount for century lock display.
  // Rounds to the nearest valid 1-2-5 denomination (same as Denomination::nearest in Rust).
  function nearestDenomination(value: number): number {
    if (value <= 0) return 1;
    let power = 1;
    while (power <= value / 10) power *= 10;
    const candidates = [1 * power, 2 * power, 5 * power, 10 * power];
    let best = candidates[0];
    let bestDiff = Infinity;
    for (const c of candidates) {
      const diff = Math.abs(c - value);
      if (diff < bestDiff) { bestDiff = diff; best = c; }
    }
    return best;
  }
  $: perBlockVess = centuryLock && amountSats
    ? nearestDenomination(Math.ceil(amountSats / 52560))
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
      <label class="block text-sm text-gray-400 mb-1">Duration: {effectiveYears} year{effectiveYears === 1 ? '' : 's'}</label>
      <input
        type="range"
        bind:value={durationYears}
        min="0.1"
        max="10"
        step="0.1"
        class="w-full accent-[#88cddf]"
        disabled={centuryLock}
        class:opacity-30={centuryLock}
      />
      <div class="flex justify-between text-xs text-gray-600 mt-1">
        <span>0.1 yr</span>
        <span>10 yr</span>
      </div>

      <!-- ── century lock toggle ── -->
      <label class="flex items-start gap-3 mt-3 p-3 rounded-lg cursor-pointer transition-colors hover:bg-[#252d30]/50"
        style="background: {centuryLock ? '#3d1515' : '#252d30'}; border: 1px solid {centuryLock ? '#cc3333' : '#323a3e'}">
        <input type="checkbox" bind:checked={centuryLock} class="mt-0.5 accent-[#cc3333]" />
        <div>
          <span class="text-sm font-medium" style="color: {centuryLock ? '#ff6666' : '#999'}">Century Lock</span>
          <p class="text-xs text-gray-500 mt-0.5">Lock your bitcoin for 100 years and receive a steady Vess faucet — one bill per Bitcoin block.</p>
          {#if centuryLock && perBlockVess > 0}
            <p class="text-xs mt-1" style="color: '#ff6666'">{perBlockVess} Vess / block · no Vichor required</p>
          {/if}
        </div>
      </label>
    </div>

    <div class="bg-[#252d30] rounded-lg p-4 space-y-2 text-sm">
      {#if !centuryLock}
        <div class="flex justify-between">
          <span class="text-gray-400">Vichor Required</span>
          <span class:text-[#88cddf]={vichorRequired > 0} class:text-gray-500={vichorRequired === 0}>
            {vichorRequired}
          </span>
        </div>
      {/if}
      {#if !centuryLock && vichorRequired > 0}
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