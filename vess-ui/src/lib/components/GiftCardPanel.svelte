<script lang="ts">
  // GiftCardPanel.svelte — browse and purchase gift cards via Bitrefill API

  type GiftCard = {
    id: string;
    name: string;
    description: string;
    image_url?: string;
    price_usd: number;
    currency: string;
  };

  let catalog: GiftCard[] = [];
  let loading = false;
  let error = "";

  async function loadCatalog() {
    loading = true;
    error = "";
    try {
      const resp = await fetch("/api/giftcard/catalog");
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      catalog = data.cards || [];
    } catch (e: any) {
      error = e.message || "Failed to load catalog";
    } finally {
      loading = false;
    }
  }

  // Load on mount
  loadCatalog();

  // ── helpers ──
  function formatPrice(cents: number): string {
    return `$${(cents / 100).toFixed(2)}`;
  }
</script>

<div class="space-y-4">
  <h1 class="text-xl font-bold text-[#ec4899]">🎁 Gift Cards</h1>
  <p class="text-sm text-gray-400">
    Purchase gift cards using your crypto balance via Bitrefill.
  </p>

  {#if loading}
    <p class="text-sm text-gray-400">Loading catalog...</p>
  {:else if error}
    <p class="text-sm text-red-400">{error}</p>
  {:else if catalog.length === 0}
    <p class="text-sm text-gray-400">No gift cards available.</p>
  {:else}
    <div class="grid grid-cols-2 gap-3 max-h-96 overflow-y-auto">
      {#each catalog as card}
        <button
          class="bg-[#1a2124] border border-white/5 rounded-xl p-3 text-left hover:border-[#ec4899]/30 transition-colors space-y-1"
        >
          {#if card.image_url}
            <img src={card.image_url} alt={card.name} class="w-full h-16 object-contain rounded-lg mb-2" />
          {/if}
          <p class="text-sm font-medium text-white truncate">{card.name}</p>
          <p class="text-xs text-gray-500">{card.description}</p>
          <p class="text-sm font-semibold text-[#ec4899]">{formatPrice(card.price_usd)}</p>
        </button>
      {/each}
    </div>
  {/if}
</div>
