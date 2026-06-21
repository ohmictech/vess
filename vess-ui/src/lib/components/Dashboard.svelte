<script lang="ts">
  import { onMount } from "svelte";
  import { getBalance, getBills, type BalanceData, type BillInfo } from "../rpc/client";

  let balance: BalanceData | null = null;
  let bills: BillInfo[] = [];
  let loading = true;
  let error = "";

  onMount(async () => {
    try {
      [balance, bills] = await Promise.all([getBalance(), getBills()]);
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  });
</script>

<div class="w-full max-w-5xl mx-auto">
  <h1 class="text-xl md:text-2xl font-bold mb-4 md:mb-6">Dashboard</h1>

  {#if loading}
    <p class="text-gray-500">Loading...</p>
  {:else if error}
    <div class="bg-red-900/20 border border-red-800 rounded-lg p-4 text-red-400 text-sm">
      {error}
    </div>
  {:else}
    <!-- Balance cards — stack on mobile, row on desktop -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 md:gap-4 mb-6 md:mb-8">
      <div class="bg-[#1c2224] rounded-xl p-4 md:p-5 border border-[#2a3033]">
        <div class="text-sm text-gray-500 mb-1">Vess Balance</div>
        <div class="text-2xl md:text-3xl font-bold text-[#5fb5d2]">{balance?.balance ?? 0}</div>
        <div class="text-xs text-gray-600 mt-1">sat-block credits</div>
      </div>
      <div class="bg-[#1c2224] rounded-xl p-4 md:p-5 border border-[#2a3033]">
        <div class="text-sm text-gray-500 mb-1">Bills</div>
        <div class="text-2xl md:text-3xl font-bold text-white">{balance?.bill_count ?? 0}</div>
        <div class="text-xs text-gray-600 mt-1">bearer instruments</div>
      </div>
      <div class="bg-[#1c2224] rounded-xl p-4 md:p-5 border border-[#2a3033] sm:col-span-2 lg:col-span-1">
        <div class="text-sm text-gray-500 mb-1">Watch-Only</div>
        <div class="text-2xl md:text-3xl font-bold text-gray-300">{balance?.watch_only_balance ?? 0}</div>
        <div class="text-xs text-gray-600 mt-1">unclaimed bills</div>
      </div>
    </div>

    <!-- Bill list -->
    <div class="bg-[#1c2224] rounded-xl border border-[#2a3033] p-4 md:p-5">
      <h2 class="text-lg font-semibold mb-4">Bills</h2>
      {#if bills.length === 0}
        <p class="text-gray-500 text-sm">No bills yet. Lock some BTC via Time-Lock Mint.</p>
      {:else}
        <!-- Horizontal scroll on mobile, full table on desktop -->
        <div class="-mx-4 md:mx-0 overflow-x-auto">
          <div class="inline-block min-w-full align-middle px-4 md:px-0">
            <table class="w-full text-sm">
              <thead>
                <tr class="text-gray-500 border-b border-[#2a3033]">
                  <th class="text-left py-2 pr-4 whitespace-nowrap">Denomination</th>
                  <th class="text-left py-2 pr-4 whitespace-nowrap">Asset</th>
                  <th class="text-left py-2 pr-4 hidden sm:table-cell">Mint ID</th>
                  <th class="text-right py-2 whitespace-nowrap">Depth</th>
                </tr>
              </thead>
              <tbody>
                {#each bills as bill}
                  <tr class="border-b border-[#2a3033]/50 hover:bg-[#252d30]/30">
                    <td class="py-2 pr-4 font-medium">{bill.denomination}</td>
                    <td class="py-2 pr-4">
                      <span class="px-2 py-0.5 rounded text-xs {bill.asset === 'btc' ? 'bg-[#5fb5d2]/20 text-[#5fb5d2]' : 'bg-[#ccff00]/20 text-[#ccff00]'}">
                        {bill.asset}
                      </span>
                    </td>
                    <td class="py-2 pr-4 text-gray-400 font-mono text-xs hidden sm:table-cell">{bill.mint_id.slice(0, 16)}...</td>
                    <td class="py-2 text-right text-gray-400">{bill.chain_depth}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </div>
      {/if}
    </div>
  {/if}
</div>
