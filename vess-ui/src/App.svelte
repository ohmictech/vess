<script lang="ts">
  import { fade, scale } from "svelte/transition";
  import { onMount, onDestroy } from "svelte";
  import HexWallet from "./lib/components/HexWallet.svelte";
  import SendPanel from "./lib/components/SendPanel.svelte";
  import ReceivePanel from "./lib/components/ReceivePanel.svelte";
  import TagsPanel from "./lib/components/TagsPanel.svelte";
  import NodeStatus from "./lib/components/NodeStatus.svelte";
  import MintPanel from "./lib/components/MintPanel.svelte";
  import Onboard from "./lib/components/Onboard.svelte";
  import { listSwapOffers, createSwapOffer, getBalance, getNodeInfo, type SwapOffer } from "./lib/rpc/client";
  import { biometricGate } from "./lib/auth";
  import QRCode from "qrcode";

  type Tab = "wallet" | "send" | "receive" | "tags" | "mint" | "node" | "bitcoin_receive" | "buy_vichor" | "buy_btc";
  type Asset = "vess" | "bitcoin" | "vichor";

  const ASSETS: Asset[] = ["vess", "bitcoin", "vichor"];
  const ASSET_COLOR: Record<string, string> = { vess: "#88cddf", bitcoin: "#f28e13", vichor: "#ccff00" };

  let onboarded = false;
  let popup: Tab | null = null;
  let currentAsset: Asset = "vess";
  let btcAddress = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
  let btcCopied = false;
  let btcQr = "";

  // ── peer count ──
  let peerCount = 0;
  let networkSize = 0;
  let peerPollTimer: ReturnType<typeof setInterval> | null = null;

  async function refreshPeerCount() {
    try {
      const info = await getNodeInfo();
      peerCount = info.peer_count;
      networkSize = info.estimated_network_size;
    } catch { /* node offline */ }
  }

  // ── swap state ──
  let swapOffers: SwapOffer[] = [];
  let swapLoading = false;
  let showCreateOffer = false;
  let swapAssetA: Asset = "vess";
  let swapAssetB: Asset = "vichor";
  let swapPct: number = 50;          // % of balance to offer
  let swapPriceLog: number = 500;    // log-scale price (0–1000 → 1–9999)
  $: swapPrice = Math.round(Math.pow(10, (swapPriceLog / 1000) * Math.log10(9999))) || 1;
  $: swapPriceUnit = swapAssetA === "bitcoin" || swapAssetB === "bitcoin"
    ? (swapAssetA === "bitcoin" ? swapAssetB : swapAssetA)
    : swapUnitB;
  $: swapColor = ASSET_COLOR[swapAssetB] || "#88cddf";
  $: swapUnitA = swapAssetA === "bitcoin" ? "sat" : swapAssetA;
  $: swapUnitB = swapAssetB === "bitcoin" ? "sat" : swapAssetB;
  let creatingOffer = false;
  let swapBalances: Record<string, number> = {};
  $: swapOfferAmount = Math.floor((swapBalances[swapAssetA] || 0) * swapPct / 100);
  $: swapWantAmount = swapAssetA === "bitcoin"
    ? swapOfferAmount * swapPrice
    : swapAssetB === "bitcoin"
      ? Math.floor(swapOfferAmount / swapPrice)
      : swapOfferAmount * swapPrice;

  onMount(() => {
    QRCode.toDataURL(btcAddress, { width: 256, margin: 1 }).then(url => btcQr = url);
    // Check if onboarding was already completed
    if (localStorage.getItem("vess_onboarded") === "1") onboarded = true;
    // Start peer count polling
    refreshPeerCount();
    peerPollTimer = setInterval(refreshPeerCount, 15_000);
  });

  onDestroy(() => {
    if (peerPollTimer) clearInterval(peerPollTimer);
  });

  function onOnboardReady() {
    onboarded = true;
    localStorage.setItem("vess_onboarded", "1");
  }

  function onNavigate(tab: Tab) {
    navigator.vibrate?.(5);
    popup = tab;
    if (tab === "buy_vichor") {
      swapAssetA = currentAsset;
      swapAssetB = currentAsset === "vichor" ? "vess" : "vichor";
      showCreateOffer = false;
      swapPct = 50;
      swapPriceLog = 500;
      refreshSwapBalances();
      loadSwapOffers();
    }
  }

  async function refreshSwapBalances() {
    try {
      const b = await getBalance();
      swapBalances = {
        vess: b.balance || 0,
        bitcoin: b.watch_only_balance || 0,
        vichor: b.vichor_balance || 0,
      };
    } catch { /* node offline */ }
  }

  async function loadSwapOffers() {
    swapLoading = true;
    try {
      swapOffers = await listSwapOffers(swapAssetA, swapAssetB);
    } catch {
      swapOffers = [];
    } finally {
      swapLoading = false;
    }
  }

  function flipSwapAssets() {
    const a = swapAssetA;
    swapAssetA = swapAssetB;
    swapAssetB = a;
    loadSwapOffers();
  }

  function closePopup() {
    navigator.vibrate?.(4);
    popup = null;
  }

  function copyBtc() {
    navigator.vibrate?.(6);
    navigator.clipboard.writeText(btcAddress);
    btcCopied = true;
    setTimeout(() => btcCopied = false, 2000);
  }

  function buyBtc() {
    window.open("https://buy.moonpay.com?apiKey=YOUR_API_KEY&currencyCode=btc", "_blank");
  }

  function syncPriceFromInput(e: Event) {
    const v = parseInt((e.target as HTMLInputElement).value);
    if (v && v >= 1 && v <= 9999) {
      swapPriceLog = Math.round(Math.log10(v) / Math.log10(9999) * 1000);
    }
  }

  function openCreateOffer() {
    swapPct = 50;
    swapPriceLog = 500;
    showCreateOffer = true;
  }

  async function handleCreateOffer() {
    if (!swapOfferAmount || !swapWantAmount) return;
    if (!await biometricGate()) return;
    creatingOffer = true;
    try {
      await createSwapOffer(swapAssetA, swapOfferAmount, swapAssetB, swapWantAmount, "open", 86400);
      showCreateOffer = false;
      refreshSwapBalances();
      loadSwapOffers();
    } catch (e) {
      console.error(e);
    } finally {
      creatingOffer = false;
    }
  }
</script>

<div class="h-dvh w-full overflow-hidden bg-[#1a1a1a]">
  {#if !onboarded}
    <Onboard on:ready={onOnboardReady} />
  {:else}
  <!-- HexWallet always visible -->
  <HexWallet bind:selectedAsset={currentAsset} onNavigate={(t) => onNavigate(t as Tab)} />

  <!-- Popup overlay -->
  {#if popup}
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div
      class="fixed inset-0 z-50 flex items-center justify-center p-4"
      on:click={closePopup}
      role="dialog"
      aria-modal="true"
      tabindex="-1"
    >
      <!-- Backdrop -->
      <div class="absolute inset-0 bg-black/60" transition:fade={{ duration: 200 }}></div>
      <!-- Popup card — click on card stops propagation -->
      <div
        class="relative bg-gradient-to-b from-[#1e2629] to-[#1c2224] rounded-2xl p-6 w-full {popup === 'bitcoin_receive' ? 'max-w-xs' : 'max-w-md'} max-h-[85vh] overflow-y-auto"
        style="box-shadow: 0 0 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.04), inset 0 1px 0 rgba(255,255,255,0.02)"
        transition:scale={{ duration: 200, start: 0.92 }}
        on:click={(e) => e.stopPropagation()}
        on:keydown={(e) => e.stopPropagation()}
        role="presentation"
      >
        {#if popup === "send"}
          <SendPanel asset={currentAsset} />
        {:else if popup === "receive"}
          <ReceivePanel asset={currentAsset} />
        {:else if popup === "tags"}
          <TagsPanel asset={currentAsset} />
        {:else if popup === "mint"}
          <MintPanel asset={currentAsset} />
        {:else if popup === "node"}
          <NodeStatus asset={currentAsset} />
        {:else if popup === "bitcoin_receive"}
          <div class="space-y-3 flex flex-col items-center">
            <!-- QR Code — click to copy -->
            <button
              on:click={copyBtc}
              class="w-64 h-64 bg-white rounded-xl flex items-center justify-center border-2 border-dashed border-[#f28e13]/30 hover:border-[#f28e13]/60 transition-colors overflow-hidden p-2"
            >
              {#if btcQr}
                <img src={btcQr} alt="BTC address QR" class="w-full h-full" />
              {:else}
                <span class="text-gray-400 text-xs">loading...</span>
              {/if}
            </button>
            <p class="text-xs text-gray-500">
              {btcCopied ? "Copied!" : "tap QR to copy address"}
            </p>
          </div>
        {:else if popup === "buy_btc"}
          <div class="space-y-4 text-center">
            <h1 class="text-xl font-bold" style="color: #f28e13">Buy Bitcoin</h1>
            <p class="text-sm text-gray-400">Purchase BTC via Moonpay onramp.</p>
            <button
              on:click={buyBtc}
              class="w-full py-3 rounded-lg font-semibold bg-[#f28e13] hover:bg-[#d67d0f] text-black transition-colors"
            >
              BUY BTC
            </button>
          </div>
        {:else if popup === "buy_vichor"}
          <div class="space-y-4">
            <h1 class="text-xl font-bold" style="color: {swapColor}">SWAP</h1>
            <p class="text-sm text-gray-400">Atomic cross-asset trading via DHT offers.</p>

            <!-- asset selectors -->
            <div class="flex items-center gap-2">
              <div class="flex-1">
                <label class="block text-xs text-gray-500 mb-1">You have</label>
                <select bind:value={swapAssetA} on:change={loadSwapOffers}
                  class="w-full rounded-lg px-3 py-2 text-sm bg-[#252d30] text-white border border-[#323a3e] focus:outline-none focus:border-[{swapColor}]"
                  style="border-color: {swapColor}40">
                  {#each ASSETS as a}
                    {#if a !== swapAssetB}
                      <option value={a}>{a.toUpperCase()}</option>
                    {/if}
                  {/each}
                </select>
              </div>
              <button on:click={flipSwapAssets}
                class="mt-5 w-8 h-8 rounded-full flex items-center justify-center text-xs bg-[#252d30] hover:bg-[#323a3e] text-gray-400 transition-colors"
                title="flip assets">⇄</button>
              <div class="flex-1">
                <label class="block text-xs text-gray-500 mb-1">You want</label>
                <select bind:value={swapAssetB} on:change={loadSwapOffers}
                  class="w-full rounded-lg px-3 py-2 text-sm bg-[#252d30] text-white border border-[#323a3e] focus:outline-none"
                  style="color: {swapColor}; border-color: {swapColor}40">
                  {#each ASSETS as b}
                    {#if b !== swapAssetA}
                      <option value={b}>{b.toUpperCase()}</option>
                    {/if}
                  {/each}
                </select>
              </div>
            </div>

            {#if showCreateOffer}
              <div class="bg-[#252d30]/40 rounded-lg p-4 space-y-3">
                <h2 class="text-sm font-semibold text-white">Create Swap Offer</h2>

                <!-- % of balance slider -->
                <div>
                  <div class="flex justify-between text-xs mb-1">
                    <span class="text-gray-500">% of {swapAssetA} balance</span>
                    <span style="color: {swapColor}">{swapPct}% → {swapOfferAmount.toLocaleString()} {swapUnitA}</span>
                  </div>
                  <input type="range" bind:value={swapPct} min="1" max="100" step="1"
                    class="w-full" style="accent-color: {swapColor}" />
                  <div class="flex justify-between text-xs text-gray-600 mt-0.5"><span>1%</span><span>100%</span></div>
                </div>

                <!-- price rate slider + input -->
                <div>
                  <div class="flex justify-between text-xs mb-1">
                    <span class="text-gray-500">Price rate</span>
                    <div class="flex items-center gap-1">
                      <span style="color: {swapColor}">1 {swapAssetA === "bitcoin" || swapAssetB === "bitcoin" ? "sat" : swapUnitA} =</span>
                      <input type="number"
                        value={swapPrice}
                        on:input={syncPriceFromInput}
                        min="1" max="9999" step="1"
                        class="w-20 rounded px-2 py-0.5 text-xs text-right bg-[#1a1a1a] border border-[#323a3e] focus:outline-none focus:border-current transition-colors"
                        style="color: {swapColor}; border-color: {swapColor}40" />
                    </div>
                  </div>
                  <input type="range" bind:value={swapPriceLog} min="0" max="1000" step="1"
                    class="w-full" style="accent-color: {swapColor}" />
                  <div class="flex justify-between text-xs text-gray-600 mt-0.5"><span>1</span><span>9999</span></div>
                </div>

                {#if swapOfferAmount > 0 && swapWantAmount > 0}
                  <div class="text-xs rounded px-2 py-1.5" style="color: {swapColor}; background: {swapColor}18">
                    Total: <span class="font-medium">{swapWantAmount.toLocaleString()}</span> {swapUnitB}
                    for <span class="font-medium">{swapOfferAmount.toLocaleString()}</span> {swapUnitA}
                  </div>
                {/if}

                <div class="flex gap-2">
                  <button on:click={() => showCreateOffer = false}
                    class="flex-1 py-2 rounded-lg text-xs font-medium bg-[#252d30] hover:bg-[#323a3e] text-gray-400 transition-colors">cancel</button>
                  <button on:click={handleCreateOffer}
                    disabled={creatingOffer || swapOfferAmount < 1}
                    class="flex-1 py-2 rounded-lg text-xs font-semibold text-black transition-colors disabled:opacity-50"
                    style="background: {swapColor}">{creatingOffer ? "creating..." : "create offer"}</button>
                </div>
              </div>
            {/if}

            <!-- offers list -->
            {#if swapLoading}
              <div class="flex justify-center py-8"><span class="text-gray-500 text-sm">loading offers...</span></div>
            {:else if swapOffers.length === 0}
              <div class="text-sm text-gray-600 py-4 text-center">no swap offers for {swapAssetA}/{swapAssetB} yet.</div>
            {:else}
              <div class="space-y-2">
                {#each swapOffers as offer}
                  {@const rate = (offer.want_amount / offer.offer_amount).toFixed(4)}
                  <div class="bg-[#252d30]/40 rounded-lg p-3">
                    <div class="flex items-center justify-between">
                      <div>
                        <div class="text-sm font-medium text-white">{offer.seller_tag}</div>
                        <div class="text-xs text-gray-500">{offer.offer_amount.toLocaleString()} {offer.offer_asset} → {offer.want_amount.toLocaleString()} {offer.want_asset}</div>
                      </div>
                      <button class="px-3 py-1.5 rounded-lg text-xs font-semibold text-black transition-colors"
                        style="background: {swapColor}">swap</button>
                    </div>
                    <div class="text-xs mt-1" style="color: {swapColor}">rate: {rate} {offer.want_asset}/{offer.offer_asset}</div>
                  </div>
                {/each}
              </div>
            {/if}

            <button on:click={openCreateOffer}
              class="w-full mt-2 py-2 rounded-lg text-xs font-semibold border border-dashed transition-colors"
              style="border-color: {swapColor}30; color: {swapColor}">
              {showCreateOffer ? "close" : "+ create offer"}
            </button>
          </div>
        {/if}
      </div>
    </div>
  {/if}
{/if}

  <!-- ── peer count (always visible, bottom-right) ── -->
  <div
    class="fixed bottom-3 right-3 z-40 flex items-center gap-1.5 text-xs text-gray-500 select-none pointer-events-none"
    style="text-shadow: 0 1px 4px rgba(0,0,0,0.6)"
  >
    <span class="inline-block w-1.5 h-1.5 rounded-full" style="background: {peerCount > 0 ? '#88cddf' : '#555'}"></span>
    {peerCount > 0 ? `${peerCount} peer${peerCount === 1 ? '' : 's'}` : 'offline'}
    {#if networkSize > 0 && networkSize !== peerCount}
      <span class="text-gray-600">· est {networkSize}</span>
    {/if}
  </div>
</div>

