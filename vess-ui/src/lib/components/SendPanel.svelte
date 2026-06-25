<script lang="ts">
  import { sendPayment, sendBitcoin, lookupTag, type TagInfo } from "../rpc/client";
  import { biometricGate } from "../auth";

  export let asset: "vess" | "bitcoin" | "vichor" = "vess";

  // ── Vess / Vichor fields ──────────────────────────────
  let tag = "";
  let tagResolved: TagInfo | null = null;
  let tagError = "";
  let tagTimer: ReturnType<typeof setTimeout> | null = null;
  let amountVess: number | null = null;
  let memo = "";
  let showMemo = false;
  let showContacts = false;
  let contacts: string[] = [];

  // Load contacts from localStorage, seed with placeholders
  function loadContacts() {
    const saved = localStorage.getItem("vess_contacts");
    contacts = saved ? JSON.parse(saved) : ["ALICE", "BOB", "CAROL", "DAVE", "EVE"];
  }
  loadContacts();

  function saveContact(t: string) {
    const clean = t.replace(/^\+/, "").toUpperCase();
    if (!clean || contacts.includes(clean)) return;
    contacts = [clean, ...contacts].slice(0, 20);
    localStorage.setItem("vess_contacts", JSON.stringify(contacts));
  }

  // Filter matching contacts for auto-suggest
  $: tagSuggestions = tag.length >= 1
    ? contacts.filter(c => c.startsWith(tag.replace(/^\+/, "").toUpperCase()) && c !== tag.replace(/^\+/, "").toUpperCase())
    : [];

  function selectContact(c: string) {
    tag = c;
    showContacts = false;
    onTagInput();
  }

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

  function saveTransaction(tx: { asset: string; amount: number; tag?: string; address?: string; txid: string }) {
    const saved = localStorage.getItem("vess_tx_history");
    const history = saved ? JSON.parse(saved) : [];
    history.unshift({ ...tx, time: Date.now() });
    localStorage.setItem("vess_tx_history", JSON.stringify(history.slice(0, 100)));
  }

  // Auto-lookup tag after typing stops
  function onTagInput() {
    tagResolved = null;
    tagError = "";
    if (tagTimer) clearTimeout(tagTimer);
    const clean = tag.replace("+", "").toUpperCase();
    if (!clean) return;
    if (clean.length < 2) return;

    tagTimer = setTimeout(async () => {
      try {
        const info = await lookupTag(clean);
        tagResolved = info;
        tagError = "";
        saveContact(clean);
      } catch {
        tagResolved = null;
        tagError = "tag not found";
      }
    }, 500);
  }

  // ── Send handlers ─────────────────────────────────────
  async function pasteBtc() {
    try {
      // Request clipboard permission first
      const perm = await navigator.permissions.query({ name: "clipboard-read" as any });
      if (perm.state === "denied") {
        // fallback: try anyway, some browsers allow it with user gesture
      }
      const text = await navigator.clipboard.readText();
      if (text) btcAddress = text.trim();
    } catch {
      // clipboard read denied or unsupported
    }
  }

  let scanning = false;
  let scanError = "";

  async function scanQR() {
    scanError = "";
    // Try BarcodeDetector API first
    if ("BarcodeDetector" in window) {
      try {
        const detector = new (window as any).BarcodeDetector({ formats: ["qr_code"] });
        // Use camera via file input with capture
        const input = document.createElement("input");
        input.type = "file";
        input.accept = "image/*";
        input.setAttribute("capture", "environment");
        input.onchange = async () => {
          const file = input.files?.[0];
          if (!file) return;
          try {
            const bitmap = await createImageBitmap(file);
            const barcodes = await detector.detect(bitmap);
            if (barcodes.length > 0) {
              btcAddress = barcodes[0].rawValue;
            } else {
              scanError = "no QR code found";
            }
          } catch {
            scanError = "scan failed";
          }
          scanning = false;
        };
        input.click();
        scanning = true;
        return;
      } catch { /* fall through */ }
    }
    scanError = "QR scanner not supported on this device";
  }

  async function handleSendVess() {
    if (!tag || !amountVess) return;
    if (!await biometricGate()) return;
    sending = true;
    error = "";
    result = "";
    try {
      const paymentId = await sendPayment(tag, amountVess, memo || undefined);
      saveContact(tag);
      saveTransaction({ asset, amount: amountVess, tag, txid: paymentId });
      result = `Sent ${amountVess} ${assetLabels[asset]} to ${tag} (${paymentId.slice(0, 16)}...)`;
      tag = "";
      amountVess = null;
      memo = "";
      showMemo = false;
      tagResolved = null;
    } catch (e) {
      error = String(e);
    } finally {
      sending = false;
    }
  }

  async function handleSendBitcoin() {
    if (!btcAddress || !btcAmount) return;
    if (!await biometricGate()) return;
    sending = true;
    error = "";
    result = "";
    try {
      const txid = await sendBitcoin(btcAddress, btcAmount, memo || undefined);
      saveTransaction({ asset: "bitcoin", amount: btcAmount, address: btcAddress, txid });
      result = `Sent ${btcAmount} sats to ${btcAddress.slice(0, 12)}... (${txid.slice(0, 16)}...)`;
      btcAddress = "";
      btcAmount = null;
      memo = "";
      showMemo = false;
    } catch (e) {
      error = String(e);
    } finally {
      sending = false;
    }
  }

  $: canSendVess = !!tag && !!amountVess && amountVess > 0;
  $: canSendBtc = !!btcAddress && !!btcAmount && btcAmount > 0;
  $: assetColor = asset === "vess" ? "#88cddf" : asset === "vichor" ? "#ccff00" : "#f28e13";
  $: inputClass = "w-full rounded-lg px-4 py-3 text-lg text-[#1a1a1a] placeholder-[#3d484c] focus:outline-none transition-colors";
  $: inputStyle = `background: ${assetColor}18`;
  $: amountLabel = asset === "vess" ? "vess amount" : asset === "vichor" ? "vichor amount" : "sats amount";
</script>

<div class="space-y-4">

  {#if asset === "bitcoin"}
    <!-- ── Bitcoin send ──────────────────────────── -->
    <div class="relative">
      <label class="block text-xs text-gray-500 mb-1">btc address</label>
      <div class="flex gap-2">
        <input
          bind:value={btcAddress}
          placeholder="bc1q..."
          class="flex-1 min-w-0 rounded-lg px-4 py-3 text-lg placeholder-[#3d484c] focus:outline-none transition-colors font-mono box-border"
          style={inputStyle}
        />
        <button on:click={pasteBtc}
          class="w-12 flex items-center justify-center rounded-lg bg-[#252d30] hover:bg-[#323a3e] transition-colors shrink-0" title="Paste">
          <svg class="w-5 h-5" fill="none" stroke="#f28e13" stroke-width="1.5" viewBox="0 0 24 24"><rect x="8" y="2" width="8" height="4" rx="1"/><path d="M6 6h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2z"/><path d="M10 14l2 2 4-4"/></svg>
        </button>
        <button on:click={scanQR}
          class="w-12 flex items-center justify-center rounded-lg bg-[#252d30] hover:bg-[#323a3e] transition-colors shrink-0" title="Scan QR">
          <svg class="w-5 h-5" fill="none" stroke="#f28e13" stroke-width="1.5" viewBox="0 0 24 24"><path d="M3 3h5v5H3V3z"/><path d="M16 3h5v5h-5V3z"/><path d="M3 16h5v5H3v-5z"/><path d="M16 16h5v5h-5v-5z"/><path d="M11 7v2"/><path d="M11 15v2"/><path d="M7 11h2"/><path d="M15 11h2"/></svg>
        </button>
      </div>
      {#if scanning}
        <p class="text-xs text-gray-400 mt-1">scanning...</p>
      {:else if scanError}
        <p class="text-xs text-red-400 mt-1">{scanError}</p>
      {/if}
    </div>

    <div>
      <label class="block text-xs text-gray-500 mb-1">{amountLabel}</label>
      <input
        type="number"
        bind:value={btcAmount}
        min="1"
        step="1"
        placeholder="0"
        on:input={() => { if (btcAmount !== null) btcAmount = Math.floor(btcAmount); }}
        class="w-full rounded-lg px-4 py-3 text-lg placeholder-[#3d484c] focus:outline-none transition-colors box-border"
        style={inputStyle}
      />
    </div>

    <!-- memo toggle -->
    {#if showMemo}
      <div>
        <input
          bind:value={memo}
          placeholder='memo...'
          class="w-full rounded-lg px-4 py-2 text-sm text-[#1a1a1a] placeholder-[#3d484c] focus:outline-none transition-colors"
          style={inputStyle}
        />
      </div>
    {:else}
      <button on:click={() => showMemo = true}
        class="text-xs text-gray-500 hover:text-gray-300 transition-colors">
        + add memo
      </button>
    {/if}

    <!-- big icon send button -->
    <button
      on:click={handleSendBitcoin}
      disabled={sending || !canSendBtc}
      class="w-full py-4 rounded-xl flex items-center justify-center gap-2 transition-all duration-200 disabled:opacity-30 hover:scale-[1.02] active:scale-[0.98]"
      style="background: {assetColor}; color: #1a1a1a;"
    >
      {#if sending}
        <svg class="w-7 h-7 animate-spin" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke-opacity="0.3"/><path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/></svg>
      {:else}
        <svg class="w-7 h-7" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M22 2L11 13" stroke-linecap="round" stroke-linejoin="round"/><path d="M22 2l-7 20-4-9-9-4 20-7z" stroke-linecap="round" stroke-linejoin="round"/></svg>
      {/if}
    </button>

  {:else}
    <!-- ── Vess / Vichor send ────────────────────── -->

    <!-- vesstag input with contacts button -->
    <div class="relative">
      <label class="block text-xs text-gray-500 mb-1">vesstag</label>
      <div class="flex gap-6">
        <div class="relative flex-1">
          <span class="absolute left-4 top-1/2 -translate-y-1/2 text-lg font-bold pointer-events-none" style="color: {assetColor}">+</span>
          <input
            bind:value={tag}
            on:input={onTagInput}
            placeholder="ALICE"
            class="w-full min-w-0 rounded-lg pl-8 pr-8 py-3 text-lg placeholder-current placeholder-opacity-30 focus:outline-none transition-colors uppercase box-border text-center"
            style={inputStyle}
          />
        </div>
        <button on:click={() => showContacts = !showContacts}
          class="w-12 flex items-center justify-center rounded-lg bg-[#252d30] hover:bg-[#323a3e] transition-colors shrink-0"
          title="contacts">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="color: {assetColor}">
            <circle cx="9" cy="7" r="3"/><circle cx="15" cy="16" r="3"/>
            <path d="M4 17c0-2.8 2.2-5 5-5h2"/><path d="M13 12h2c2.8 0 5 2.2 5 5"/>
          </svg>
        </button>
      </div>

      <!-- auto-suggest dropdown -->
      {#if tagSuggestions.length > 0}
        <div class="absolute left-0 right-14 mt-1 bg-[#1e2629] border border-[#323a3e] rounded-lg overflow-hidden z-10 shadow-lg">
          {#each tagSuggestions as s}
            <button on:click={() => selectContact(s)}
              class="w-full px-4 py-2.5 text-left text-sm text-gray-300 hover:bg-[#252d30] transition-colors uppercase">
              +{s}
            </button>
          {/each}
        </div>
      {/if}

      <!-- contacts dropdown -->
      {#if showContacts}
        <div class="absolute right-0 top-full mt-1 w-44 bg-[#1e2629] border border-[#323a3e] rounded-lg overflow-hidden z-10 shadow-lg max-h-52 overflow-y-auto">
          <div class="px-3 py-2 text-xs text-gray-500 border-b border-[#2a3033]">recent</div>
          {#each contacts as c}
            <button on:click={() => selectContact(c)}
              class="w-full px-4 py-2.5 text-left text-sm text-gray-300 hover:bg-[#252d30] transition-colors uppercase flex items-center gap-2">
              <span class="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0" style="background: {assetColor}18; color: {assetColor}">{c[0]}</span>
              +{c}
            </button>
          {/each}
        </div>
      {/if}

      {#if tagResolved}
        <p class="text-xs text-green-400 mt-1">✓ {tagResolved.tag} → {tagResolved.address.slice(0, 20)}...</p>
      {:else if tagError}
        <p class="text-xs text-red-400 mt-1">{tagError}</p>
      {:else if tag.length >= 2}
        <p class="text-xs text-gray-600 mt-1">resolving...</p>
      {/if}
    </div>

    <div>
      <label class="block text-xs text-gray-500 mb-1">{amountLabel}</label>
      <input
        type="number"
        bind:value={amountVess}
        min="1"
        step="1"
        placeholder="0"
        on:input={() => { if (amountVess !== null) amountVess = Math.floor(amountVess); }}
        class="w-full min-w-0 rounded-lg px-4 py-3 text-lg placeholder-[#3d484c] focus:outline-none transition-colors box-border"
        style={inputStyle}
      />
    </div>

    <!-- memo toggle -->
    {#if showMemo}
      <div>
        <input
          bind:value={memo}
          placeholder='memo...'
          class="w-full rounded-lg px-4 py-2 text-sm text-[#1a1a1a] placeholder-[#3d484c] focus:outline-none transition-colors"
          style={inputStyle}
        />
      </div>
    {:else}
      <button on:click={() => showMemo = true}
        class="text-xs text-gray-500 hover:text-gray-300 transition-colors">
        + add memo
      </button>
    {/if}

    <!-- big icon send button -->
    <button
      on:click={handleSendVess}
      disabled={sending || !canSendVess}
      class="w-full py-4 rounded-xl flex items-center justify-center gap-2 transition-all duration-200 disabled:opacity-30 hover:scale-[1.02] active:scale-[0.98]"
      style="background: {assetColor}; color: #1a1a1a;"
    >
      {#if sending}
        <svg class="w-7 h-7 animate-spin" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke-opacity="0.3"/><path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/></svg>
      {:else}
        <svg class="w-7 h-7" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M22 2L11 13" stroke-linecap="round" stroke-linejoin="round"/><path d="M22 2l-7 20-4-9-9-4 20-7z" stroke-linecap="round" stroke-linejoin="round"/></svg>
      {/if}
    </button>
  {/if}

  {#if result}
    <div class="bg-green-900/20 border border-green-800 rounded-lg p-3 text-green-400 text-sm">{result}</div>
  {/if}
  {#if error}
    <div class="bg-red-900/20 border border-red-800 rounded-lg p-3 text-red-400 text-sm">{error}</div>
  {/if}
</div>