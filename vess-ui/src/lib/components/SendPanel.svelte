<script lang="ts">
  import { sendPayment, sendBitcoin, lookupTag, type TagInfo } from "../rpc/client";

  export let asset: "vess" | "bitcoin" | "vichor" = "vess";

  // ── Vess / Vichor fields ──────────────────────────────
  let tag = "";
  let tagResolved: TagInfo | null = null;
  let tagError = "";
  let tagTimer: ReturnType<typeof setTimeout> | null = null;
  let amountVess: number | null = null;
  let memo = "";

  // ── Bitcoin fields ────────────────────────────────────
  let btcAddress = "";
  let btcAmount: number | null = null;

  // ── Shared ────────────────────────────────────────────
  let sending = false;
  let result = "";
  let error = "";

  const assetLabels: Record<string, string> = {
    vess: "Vess",
    bitcoin: "BTC",
    vichor: "Vichor",
  };

  // Auto-lookup tag after typing stops
  function onTagInput() {
    tagResolved = null;
    tagError = "";
    if (tagTimer) clearTimeout(tagTimer);
    if (!tag) return;

    const clean = tag.replace("+", "");
    if (clean.length < 2) return;

    tagTimer = setTimeout(async () => {
      try {
        const info = await lookupTag(clean);
        tagResolved = info;
        tagError = "";
      } catch {
        tagResolved = null;
        tagError = "Tag not found";
      }
    }, 500);
  }

  // ── Send handlers ─────────────────────────────────────
  async function handleSendVess() {
    if (!tag || !amountVess) return;
    sending = true;
    error = "";
    result = "";
    try {
      const paymentId = await sendPayment(tag, amountVess, memo || undefined);
      result = `Sent ${amountVess} ${assetLabels[asset]} to ${tag} (${paymentId.slice(0, 16)}...)`;
      tag = "";
      amountVess = null;
      memo = "";
      tagResolved = null;
    } catch (e) {
      error = String(e);
    } finally {
      sending = false;
    }
  }

  async function handleSendBitcoin() {
    if (!btcAddress || !btcAmount) return;
    sending = true;
    error = "";
    result = "";
    try {
      const txid = await sendBitcoin(btcAddress, btcAmount);
      result = `Sent ${btcAmount} BTC to ${btcAddress.slice(0, 12)}... (${txid.slice(0, 16)}...)`;
      btcAddress = "";
      btcAmount = null;
    } catch (e) {
      error = String(e);
    } finally {
      sending = false;
    }
  }

  $: canSendVess = !!tag && !!amountVess && amountVess > 0;
  $: canSendBtc = !!btcAddress && !!btcAmount && btcAmount > 0;
  $: assetColor = asset === "vess" ? "#5fb5d2" : asset === "vichor" ? "#ccff00" : "#f28e13";
  $: inputClass = "w-full rounded-lg px-3 py-2 text-[#1a1a1a] placeholder-[#3d484c] focus:outline-none transition-colors";
  $: inputStyle = `background: ${assetColor}18`;
</script>

<div class="space-y-4">
  <h1 class="text-xl font-bold" style="color: {assetColor}">
    Send {assetLabels[asset]}
  </h1>

  {#if asset === "bitcoin"}
    <!-- ── Bitcoin send ──────────────────────────── -->
    <div>
      <label class="block text-sm text-gray-400 mb-1">Bitcoin Address</label>
      <input
        bind:value={btcAddress}
        placeholder="bc1q..."
        class={inputClass + " font-mono text-sm"}
        style={inputStyle}
      />
    </div>

    <div>
      <label class="block text-sm text-gray-400 mb-1">Amount (BTC)</label>
      <input
        type="number"
        bind:value={btcAmount}
        min="0.00000001"
        step="0.00000001"
        placeholder="0.00000000"
        class={inputClass}
        style={inputStyle}
      />
    </div>

    <button
      on:click={handleSendBitcoin}
      disabled={sending || !canSendBtc}
      class="w-full py-3 rounded-lg font-semibold transition-colors disabled:opacity-50"
      class:bg-[#5fb5d2]:hover:bg-[#4a9db8]:text-black={!sending}
      class:bg-[#323a3e]:text-gray-400={sending}
    >
      {sending ? "Sending..." : "Send BTC"}
    </button>

  {:else}
    <!-- ── Vess / Vichor send ────────────────────── -->
    <div>
      <label class="block text-sm text-gray-400 mb-1">Recipient Tag</label>
      <input
        bind:value={tag}
        on:input={onTagInput}
        placeholder="+ALICE"
        class={inputClass}
        style={inputStyle}
      />
      {#if tagResolved}
        <p class="text-xs text-green-400 mt-1">✓ {tagResolved.tag} → {tagResolved.address.slice(0, 20)}...</p>
      {:else if tagError}
        <p class="text-xs text-red-400 mt-1">{tagError}</p>
      {:else if tag.length >= 2}
        <p class="text-xs text-gray-600 mt-1">resolving...</p>
      {/if}
    </div>

    <div>
      <label class="block text-sm text-gray-400 mb-1">Amount ({assetLabels[asset]})</label>
      <input
        type="number"
        bind:value={amountVess}
        min="1"
        placeholder="0"
        class={inputClass}
        style={inputStyle}
      />
    </div>

    <div>
      <label class="block text-sm text-gray-400 mb-1">Memo (optional)</label>
      <input
        bind:value={memo}
        placeholder='e.g. "Invoice #123"'
        class={inputClass}
        style={inputStyle}
      />
    </div>

    <button
      on:click={handleSendVess}
      disabled={sending || !canSendVess}
      class="w-full py-3 rounded-lg font-semibold transition-colors disabled:opacity-50"
      class:bg-[#5fb5d2]:hover:bg-[#4a9db8]:text-black={!sending}
      class:bg-[#323a3e]:text-gray-400={sending}
    >
      {sending ? "Sending..." : `Send ${assetLabels[asset]}`}
    </button>
  {/if}

  {#if result}
    <div class="bg-green-900/20 border border-green-800 rounded-lg p-3 text-green-400 text-sm">{result}</div>
  {/if}
  {#if error}
    <div class="bg-red-900/20 border border-red-800 rounded-lg p-3 text-red-400 text-sm">{error}</div>
  {/if}
</div>