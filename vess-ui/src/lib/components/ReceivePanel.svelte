<script lang="ts">
  import { onMount } from "svelte";
  import { getVessTag } from "../rpc/client";

  export let asset: "vess" | "bitcoin" | "vichor" = "vess";

  let vesstag = "";
  let requestedAmount: number | null = null;
  let amountLocked = false;
  let copied = false;

  $: assetColor = asset === "vess" ? "#88cddf" : asset === "vichor" ? "#ccff00" : "#f28e13";
  $: glowStyle = `0 0 24px ${assetColor}40, 0 0 48px ${assetColor}20`;

  onMount(async () => {
    try { vesstag = await getVessTag(); } catch { vesstag = "LOADING..."; }
  });

  async function copyTag() {
    if (!vesstag || vesstag === "LOADING...") return;
    await navigator.clipboard.writeText(`+${vesstag}`);
    copied = true;
    setTimeout(() => copied = false, 1500);
  }

  function toggleLock() {
    amountLocked = !amountLocked;
  }
</script>

<div class="flex flex-col items-center justify-center gap-8 max-w-xs mx-auto py-4">
  <!-- glowing vesstag — text only -->
  <button
    on:click={copyTag}
    class="text-center font-mono font-bold tracking-widest transition-all duration-200 hover:scale-105 active:scale-95 tag-case leading-tight"
    style="color: {assetColor}; text-shadow: {glowStyle}; font-size: 2.25rem;"
  >
    {copied ? "COPIED!" : `+${vesstag}`}
  </button>

  <!-- amount row: input + lock checkbox -->
  <div class="flex items-center gap-4 w-full">
    <input
      type="number"
      bind:value={requestedAmount}
      disabled={amountLocked}
      min="1"
      step="1"
      placeholder="amount"
      on:input={() => { if (requestedAmount !== null) requestedAmount = Math.floor(requestedAmount); }}
      class="flex-1 min-w-0 rounded-2xl px-5 py-5 text-center placeholder-current placeholder-opacity-50 focus:outline-none transition-all duration-200 disabled:opacity-50 font-bold"
      style="background: {assetColor}12; color: {assetColor}; font-size: 4rem;"
    />
    <button on:click={toggleLock}
      class="w-14 h-14 flex items-center justify-center rounded-2xl transition-all duration-200 shrink-0"
      style="background: {amountLocked ? assetColor : assetColor + '18'}; color: {amountLocked ? '#1a1a1a' : assetColor};"
    >
      <svg class="w-7 h-7" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
        <path d="M20 6L9 17l-5-5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </button>
  </div>
</div>