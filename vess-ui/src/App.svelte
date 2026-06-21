<script lang="ts">
  import { fade, scale } from "svelte/transition";
  import { onMount } from "svelte";
  import HexWallet from "./lib/components/HexWallet.svelte";
  import SendPanel from "./lib/components/SendPanel.svelte";
  import ReceivePanel from "./lib/components/ReceivePanel.svelte";
  import TagsPanel from "./lib/components/TagsPanel.svelte";
  import NodeStatus from "./lib/components/NodeStatus.svelte";
  import MintPanel from "./lib/components/MintPanel.svelte";
  import { listSwapOffers, type SwapOffer } from "./lib/rpc/client";

  type Tab = "wallet" | "send" | "receive" | "tags" | "mint" | "node" | "bitcoin_receive" | "buy_vichor" | "buy_btc";
  type Asset = "vess" | "bitcoin" | "vichor";

  let popup: Tab | null = null;
  let currentAsset: Asset = "vess";
  let btcAddress = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
  let btcCopied = false;

  let swapOffers: SwapOffer[] = [];
  let swapLoading = false;

  onMount(() => {});

  function onNavigate(tab: Tab) {
    popup = tab;
    if (tab === "buy_vichor") loadSwapOffers();
  }

  async function loadSwapOffers() {
    swapLoading = true;
    try {
      swapOffers = await listSwapOffers();
    } catch {
      swapOffers = [];
    } finally {
      swapLoading = false;
    }
  }

  function closePopup() {
    popup = null;
  }

  function copyBtc() {
    navigator.clipboard.writeText(btcAddress);
    btcCopied = true;
    setTimeout(() => btcCopied = false, 2000);
  }

  function buyBtc() {
    window.open("https://buy.moonpay.com?apiKey=YOUR_API_KEY&currencyCode=btc", "_blank");
  }
</script>

<div class="h-dvh w-full overflow-hidden bg-[#1a1a1a]">
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
        class="relative bg-gradient-to-b from-[#1e2629] to-[#1c2224] rounded-2xl p-6 w-full max-w-md max-h-[85vh] overflow-y-auto"
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
          <div class="space-y-4">
            <!-- QR Code -->
            <div class="flex justify-center py-2">
              <div class="w-52 h-52 bg-[#1a1a1a] rounded-xl flex items-center justify-center border-2 border-dashed border-[#323a3e]">
                <span class="text-gray-600 text-xs text-center">QR Code<br />placeholder</span>
              </div>
            </div>

            <!-- Bitcoin address (clickable) -->
            <button
              on:click={copyBtc}
              class="w-full bg-[#f28e13]/10 rounded-lg px-4 py-3 text-center font-mono text-sm text-[#f28e13] hover:bg-[#f28e13]/20 transition-colors break-all"
            >
              {btcAddress}
            </button>
            {#if btcCopied}
              <p class="text-xs text-green-400 text-center -mt-2">Copied!</p>
            {/if}
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
            <h1 class="text-xl font-bold" style="color: #ccff00">Vichor Swap</h1>
            <p class="text-sm text-gray-400">Peer-to-peer swap offers from the DHT.</p>

            {#if swapLoading}
              <div class="flex justify-center py-8">
                <span class="text-gray-500 text-sm">Loading offers...</span>
              </div>
            {:else}
              <!-- Buy Vichor (sellers offering Vichor for Vess) -->
              <div>
                <h2 class="text-sm font-medium text-gray-500 mb-2">Buy Vichor</h2>
                {#each swapOffers.filter(o => !o.is_buy) as offer}
                  <div class="bg-[#252d30]/40 rounded-lg p-3 flex items-center justify-between mb-2">
                    <div>
                      <div class="text-sm font-medium text-white">{offer.seller_tag}</div>
                      <div class="text-xs text-gray-500">{offer.vichor_amount} Vichor for {offer.vess_price} Vess</div>
                    </div>
                    <button class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#ccff00]/90 hover:bg-[#ccff00] text-black transition-colors">Swap</button>
                  </div>
                {:else}
                  <div class="text-sm text-gray-600 py-2">No offers to buy Vichor.</div>
                {/each}
                <button class="w-full mt-2 py-2 rounded-lg text-xs font-semibold border border-dashed border-[#ccff00]/30 text-[#ccff00]/70 hover:bg-[#ccff00]/10 transition-colors">+ Create Buy Offer</button>
              </div>

              <!-- Sell Vichor (buyers offering Vess for Vichor) -->
              <hr class="border-[#2a3033]" />

              <div>
                <h2 class="text-sm font-medium text-gray-500 mb-2">Sell Vichor</h2>
                {#each swapOffers.filter(o => o.is_buy) as offer}
                  <div class="bg-[#252d30]/40 rounded-lg p-3 flex items-center justify-between mb-2">
                    <div>
                      <div class="text-sm font-medium text-white">{offer.seller_tag}</div>
                      <div class="text-xs text-gray-500">{offer.vichor_amount} Vichor for {offer.vess_price} Vess</div>
                    </div>
                    <button class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#ccff00]/90 hover:bg-[#ccff00] text-black transition-colors">Swap</button>
                  </div>
                {:else}
                  <div class="text-sm text-gray-600 py-2">No offers to sell Vichor.</div>
                {/each}
                <button class="w-full mt-2 py-2 rounded-lg text-xs font-semibold border border-dashed border-[#ccff00]/30 text-[#ccff00]/70 hover:bg-[#ccff00]/10 transition-colors">+ Create Sell Offer</button>
              </div>
            {/if}
          </div>
        {/if}
      </div>
    </div>
  {/if}
</div>

