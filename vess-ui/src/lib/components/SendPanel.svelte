<script lang="ts">
  import { sendPayment, lookupTag } from "../rpc/client";

  let recipientTag = "";
  let amount: number | null = null;
  let memo = "";
  let sending = false;
  let result = "";
  let error = "";
  let resolved = "";

  async function handleLookup() {
    if (!recipientTag) return;
    try {
      const tag = await lookupTag(recipientTag.replace("+", ""));
      resolved = `\u2794 ${tag.address.slice(0, 20)}...`;
    } catch {
      resolved = "Tag not found";
    }
  }

  async function handleSend() {
    if (!recipientTag || !amount) return;
    sending = true;
    error = "";
    result = "";
    try {
      const paymentId = await sendPayment(recipientTag, amount, memo || undefined);
      result = `Sent ${amount} Vess to ${recipientTag} (${paymentId.slice(0, 16)}...)`;
      recipientTag = "";
      amount = null;
      memo = "";
    } catch (e) {
      error = String(e);
    } finally {
      sending = false;
    }
  }
</script>

<div class="w-full max-w-lg mx-auto">
  <h1 class="text-2xl font-bold mb-6">Send Vess</h1>

  <div class="bg-[#1c2224] rounded-xl border border-[#2a3033] p-6 space-y-4">
    <div>
      <label class="block text-sm text-gray-400 mb-1">Recipient Tag</label>
      <div class="flex gap-2">
        <input
          bind:value={recipientTag}
          placeholder="+ALICE"
          class="flex-1 bg-[#252d30] border border-[#323a3e] rounded-lg px-3 py-2 text-white placeholder-[#5a6468] focus:outline-none focus:border-[#5fb5d2]"
        />
        <button on:click={handleLookup} class="px-3 py-2 bg-[#252d30] hover:bg-[#323a3e] rounded-lg text-sm transition-colors">
          Lookup
        </button>
      </div>
      {#if resolved}
        <p class="text-xs text-gray-500 mt-1">{resolved}</p>
      {/if}
    </div>

    <div>
      <label class="block text-sm text-gray-400 mb-1">Amount (Vess)</label>
      <input
        type="number"
        bind:value={amount}
        min="1"
        class="w-full bg-[#252d30] border border-[#323a3e] rounded-lg px-3 py-2 text-white placeholder-[#5a6468] focus:outline-none focus:border-[#5fb5d2]"
      />
    </div>

    <div>
      <label class="block text-sm text-gray-400 mb-1">Memo (optional)</label>
      <input
        bind:value={memo}
        placeholder='e.g. "Invoice #123"'
        class="w-full bg-[#252d30] border border-[#323a3e] rounded-lg px-3 py-2 text-white placeholder-[#5a6468] focus:outline-none focus:border-[#5fb5d2]"
      />
    </div>

    <button
      on:click={handleSend}
      disabled={sending || !recipientTag || !amount}
      class="w-full py-3 rounded-lg font-semibold transition-colors disabled:opacity-50"
      class:bg-[#5fb5d2]:hover:bg-[#4a9db8]:text-black={!sending}
      class:bg-[#323a3e]:text-gray-400={sending}
    >
      {sending ? "Sending..." : "Send"}
    </button>

    {#if result}
      <div class="bg-green-900/20 border border-green-800 rounded-lg p-3 text-green-400 text-sm">{result}</div>
    {/if}
    {#if error}
      <div class="bg-red-900/20 border border-red-800 rounded-lg p-3 text-red-400 text-sm">{error}</div>
    {/if}
  </div>
</div>