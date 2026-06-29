<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import { listWallets, unlockWallet, type WalletInfo } from "../rpc/client";

  const dispatch = createEventDispatcher<{ unlock: string }>();

  let wallets: WalletInfo[] = [];
  let loading = true;
  let error = "";
  let password = "";
  let selectedPath = "";

  async function loadWallets() {
    try {
      wallets = await listWallets();
      if (wallets.length === 1) {
        // Single wallet — auto-select if no password, otherwise prompt
        if (!wallets[0].has_password) {
          await unlock(wallets[0]);
          return;
        }
        selectedPath = wallets[0].path;
      } else if (wallets.length > 1) {
        selectedPath = wallets[0].path;
      }
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function unlock(wallet: WalletInfo) {
    error = "";
    loading = true;
    try {
      await unlockWallet(wallet.path, password);
      dispatch("unlock", wallet.tag);
    } catch (e: any) {
      error = e?.message || String(e) || "wrong password";
    } finally {
      loading = false;
    }
  }

  async function handleUnlock() {
    if (!selectedPath) return;
    const wallet = wallets.find(w => w.path === selectedPath);
    if (!wallet) return;
    await unlock(wallet);
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") handleUnlock();
  }

  loadWallets();
</script>

<div class="flex flex-col items-center justify-center h-dvh px-4">
  <div
    class="w-full max-w-sm bg-gradient-to-b from-[#1e2629] to-[#1c2224] rounded-2xl p-6"
    style="box-shadow: 0 0 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.04), inset 0 1px 0 rgba(255,255,255,0.02)"
  >
    <h1 class="text-xl font-bold mb-6 text-center" style="color:#88cddf">Select Wallet</h1>

    {#if loading}
      <p class="text-gray-500 text-center">Loading wallets...</p>
    {:else if wallets.length === 0}
      <p class="text-gray-500 text-center">No wallets found</p>
    {:else}
      {#if wallets.length > 1}
        <div class="mb-4">
          <label class="block text-sm text-gray-400 mb-2">Wallet</label>
          <select
            class="w-full bg-[#141819] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-1 focus:ring-[#88cddf]/40"
            bind:value={selectedPath}
          >
            {#each wallets as w}
              <option value={w.path}>
                +{w.tag} {w.has_password ? "🔒" : ""}
              </option>
            {/each}
          </select>
        </div>
      {:else}
        <p class="text-center text-gray-300 mb-4">
          Wallet: <span class="text-[#88cddf] font-semibold">+{wallets[0].tag}</span>
        </p>
      {/if}

      {#if wallets.find(w => w.path === selectedPath)?.has_password !== false}
        <div class="mb-4">
          <label class="block text-sm text-gray-400 mb-2">Password</label>
          <input
            type="password"
            class="w-full bg-[#141819] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-1 focus:ring-[#88cddf]/40"
            placeholder="Enter wallet password"
            bind:value={password}
            on:keydown={handleKeydown}
          />
        </div>
        <button
          class="w-full py-2 bg-[#88cddf] text-black font-semibold rounded-lg hover:bg-[#9ddbe8] disabled:opacity-40 transition"
          disabled={loading || !password}
          on:click={handleUnlock}
        >
          {loading ? "Unlocking..." : "Unlock"}
        </button>
      {:else}
        <button
          class="w-full py-2 bg-[#88cddf] text-black font-semibold rounded-lg hover:bg-[#9ddbe8] disabled:opacity-40 transition"
          disabled={loading}
          on:click={handleUnlock}
        >
          {loading ? "Opening..." : "Open Wallet"}
        </button>
      {/if}
    {/if}

    {#if error}
      <div class="mt-4 bg-red-900/20 rounded-lg p-3 text-red-400 text-sm text-center">
        {error}
      </div>
    {/if}
  </div>
</div>
