<script lang="ts">
  import { onMount } from "svelte";
  import { getNodeInfo, exportSeedPhrase, type NodeInfo } from "../rpc/client";
  import { biometricGate } from "../auth";

  export let asset: "vess" | "bitcoin" | "vichor" = "vess";

  let info: NodeInfo | null = null;
  let loading = true;
  let error = "";
  let notificationsOn = localStorage.getItem("vess_notifications") !== "off";
  let hapticsOn = localStorage.getItem("vess_haptics") !== "off";

  // seed phrase state
  let seedWords: string[] = [];
  let seedRevealed = false;
  let seedAuthing = false;
  let seedError = "";
  let seedCopied = false;

  // transaction history
  interface TxRecord {
    asset: string;
    amount: number;
    tag?: string;
    address?: string;
    txid: string;
    time: number;
  }
  let txHistory: TxRecord[] = [];
  let showHistory = false;

  function loadHistory() {
    const saved = localStorage.getItem("vess_tx_history");
    txHistory = saved ? JSON.parse(saved) : [];
  }
  loadHistory();

  $: assetColor = asset === "vess" ? "#88cddf" : asset === "vichor" ? "#ccff00" : "#f28e13";

  onMount(async () => {
    try {
      info = await getNodeInfo();
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  });

  function toggleNotifications() {
    notificationsOn = !notificationsOn;
    localStorage.setItem("vess_notifications", notificationsOn ? "on" : "off");
  }

  function toggleHaptics() {
    hapticsOn = !hapticsOn;
    localStorage.setItem("vess_haptics", hapticsOn ? "on" : "off");
  }

  async function revealSeed() {
    seedAuthing = true;
    seedError = "";
    seedRevealed = false;

    if (!await biometricGate()) { seedAuthing = false; return; }

    try {
      seedWords = await exportSeedPhrase();
      seedRevealed = true;
    } catch (e) {
      seedError = String(e);
    } finally {
      seedAuthing = false;
    }
  }

  function hideSeed() {
    seedRevealed = false;
    seedWords = [];
  }

  async function copySeed() {
    if (!seedWords.length) return;
    await navigator.clipboard.writeText(seedWords.join(" "));
    seedCopied = true;
    setTimeout(() => seedCopied = false, 2000);
  }
</script>

<div class="space-y-4">

  <!-- Toggles -->
  <div class="space-y-2">
    <button on:click={toggleNotifications} class="w-full flex items-center justify-between bg-[#252d30]/40 rounded-lg p-3 hover:bg-[#252d30]/60 transition-colors">
      <span class="text-sm text-gray-300">Notifications</span>
      <span class="text-xs font-medium px-2.5 py-1 rounded-full transition-colors {notificationsOn ? 'bg-[#10b981]/20 text-[#10b981]' : 'bg-[#374151] text-gray-500'}">
        {notificationsOn ? "on" : "off"}
      </span>
    </button>

    <button on:click={toggleHaptics} class="w-full flex items-center justify-between bg-[#252d30]/40 rounded-lg p-3 hover:bg-[#252d30]/60 transition-colors">
      <span class="text-sm text-gray-300">Haptic Feedback</span>
      <span class="text-xs font-medium px-2.5 py-1 rounded-full transition-colors {hapticsOn ? 'bg-[#10b981]/20 text-[#10b981]' : 'bg-[#374151] text-gray-500'}">
        {hapticsOn ? "on" : "off"}
      </span>
    </button>

    <!-- Transaction History button -->
    <button on:click={() => { loadHistory(); showHistory = !showHistory; }}
      class="w-full flex items-center justify-between bg-[#252d30]/40 rounded-lg p-3 hover:bg-[#252d30]/60 transition-colors">
      <span class="text-sm text-gray-300">Transaction History</span>
      <svg class="w-4 h-4 text-gray-500 transition-transform {showHistory ? 'rotate-180' : ''}" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>
    </button>

    {#if showHistory}
      <div class="bg-[#1a1a1a] rounded-xl border border-[#2a3033] overflow-hidden max-h-52 overflow-y-auto">
        {#if txHistory.length === 0}
          <div class="px-4 py-6 text-center text-xs text-gray-600">no transactions yet</div>
        {:else}
          {#each txHistory as tx}
            <div class="flex items-center justify-between px-4 py-3 border-b border-[#2a3033]/50 last:border-0">
              <div class="flex items-center gap-2 min-w-0">
                <span class="text-xs font-bold uppercase shrink-0" style="color: {tx.asset === 'bitcoin' ? '#f28e13' : tx.asset === 'vichor' ? '#ccff00' : '#88cddf'}">{tx.asset === 'bitcoin' ? 'BTC' : tx.asset.toUpperCase()}</span>
                <span class="text-sm text-gray-200">{tx.amount.toLocaleString()}</span>
                {#if tx.tag}
                  <span class="text-xs text-gray-500 truncate">→ +{tx.tag}</span>
                {:else if tx.address}
                  <span class="text-xs text-gray-500 truncate">→ {tx.address.slice(0, 8)}...</span>
                {/if}
              </div>
              <span class="text-xs text-gray-600 shrink-0 ml-2">{new Date(tx.time).toLocaleDateString()}</span>
            </div>
          {/each}
        {/if}
      </div>
    {/if}
  </div>

  <!-- Network Info -->
  {#if loading}
    <div class="animate-pulse space-y-3">
      <div class="h-4 bg-[#252d30] rounded w-3/4"></div>
      <div class="h-4 bg-[#252d30] rounded w-1/2"></div>
      <div class="h-4 bg-[#252d30] rounded w-2/3"></div>
    </div>
  {:else if error}
    <div class="bg-red-900/20 border border-red-800 rounded-xl p-4">
      <p class="text-red-400 text-sm">Could not connect: {error}</p>
    </div>
  {:else if info}
    <div>
      <h2 class="text-sm font-medium text-gray-500 mb-2">Network</h2>
      <dl class="space-y-2 text-sm">
        <div class="flex justify-between">
          <dt class="text-gray-400">Node ID</dt>
          <dd class="text-gray-200 font-mono text-xs">{info.node_id?.slice(0, 12)}...</dd>
        </div>
        <div class="flex justify-between">
          <dt class="text-gray-400">Peers</dt>
          <dd class="text-gray-200">{info.peer_count}</dd>
        </div>
        <div class="flex justify-between">
          <dt class="text-gray-400">Network Size</dt>
          <dd class="text-gray-200">~{info.estimated_network_size}</dd>
        </div>
        <div class="flex justify-between">
          <dt class="text-gray-400">Tags</dt>
          <dd class="text-gray-200">{info.tag_count}</dd>
        </div>
      </dl>
    </div>
  {/if}

  <!-- Seed Phrase Backup -->
  <div class="border-t border-[#2a3033] pt-4">
    <h2 class="text-sm font-medium text-gray-500 mb-3">Recovery Phrase</h2>

    {#if seedRevealed && seedWords.length > 0}
      <div class="bg-[#1a1a1a] rounded-xl p-4 border border-[#f28e13]/30 space-y-3">
        <div class="grid grid-cols-3 gap-2">
          {#each seedWords as word, i}
            <div class="flex items-center gap-1.5 text-xs">
              <span class="text-gray-600 w-5 text-right">{i + 1}.</span>
              <span class="font-mono text-gray-200">{word}</span>
            </div>
          {/each}
        </div>
        <div class="flex gap-2">
          <button on:click={copySeed}
            class="flex-1 py-2 rounded-lg text-xs font-medium bg-[#252d30] hover:bg-[#323a3e] text-gray-300 transition-colors">
            {seedCopied ? "Copied!" : "Copy words"}
          </button>
          <button on:click={hideSeed}
            class="flex-1 py-2 rounded-lg text-xs font-medium bg-[#252d30] hover:bg-[#323a3e] text-gray-400 transition-colors">
            Hide
          </button>
        </div>
      </div>
    {:else}
      <button on:click={revealSeed} disabled={seedAuthing}
        class="w-full py-3 rounded-xl flex items-center justify-center gap-2 bg-[#f28e13]/10 hover:bg-[#f28e13]/20 border border-[#f28e13]/30 transition-colors disabled:opacity-50">
        {#if seedAuthing}
          <svg class="w-4 h-4 animate-spin" fill="none" stroke="#f28e13" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke-opacity="0.2"/><path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/></svg>
          <span class="text-sm text-[#f28e13]">authenticating...</span>
        {:else}
          <svg class="w-5 h-5" fill="none" stroke="#f28e13" stroke-width="1.5" viewBox="0 0 24 24"><path d="M12 2c-3.3 0-6 2.7-6 6v2c-1.7 0-3 1.3-3 3v7c0 1.7 1.3 3 3 3h12c1.7 0 3-1.3 3-3v-7c0-1.7-1.3-3-3-3V8c0-3.3-2.7-6-6-6z"/><circle cx="12" cy="16" r="1.5"/><path d="M12 13v-1"/></svg>
          <span class="text-sm text-[#f28e13]">View Seed Phrase</span>
        {/if}
      </button>
      {#if seedError}
        <p class="text-xs text-red-400 mt-2 text-center">{seedError}</p>
      {/if}
    {/if}
  </div>
</div>