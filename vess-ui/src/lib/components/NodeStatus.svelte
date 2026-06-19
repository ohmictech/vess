<script lang="ts">
  import { onMount } from "svelte";
  import { getNodeInfo, type NodeInfo } from "../rpc/client";

  let info: NodeInfo | null = null;
  let loading = true;
  let error = "";
  let rpcUrl = "http://127.0.0.1:9821";

  onMount(async () => {
    try {
      info = await getNodeInfo();
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  });

  function saveUrl() {
    localStorage.setItem("vess_rpc_url", rpcUrl);
  }
</script>

<div class="w-full max-w-lg mx-auto">
  <h1 class="text-2xl font-bold mb-6">Node Status</h1>

  <div class="bg-gray-900 rounded-xl border border-gray-800 p-6 mb-6">
    <h2 class="text-sm font-medium text-gray-500 mb-4">RPC Connection</h2>
    <div class="flex gap-2">
      <input
        bind:value={rpcUrl}
        class="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white font-mono text-sm focus:outline-none focus:border-amber-500"
      />
      <button on:click={saveUrl} class="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm transition-colors">
        Save
      </button>
    </div>
  </div>

  {#if loading}
    <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
      <div class="animate-pulse space-y-3">
        <div class="h-4 bg-gray-800 rounded w-3/4"></div>
        <div class="h-4 bg-gray-800 rounded w-1/2"></div>
        <div class="h-4 bg-gray-800 rounded w-2/3"></div>
      </div>
    </div>
  {:else if error}
    <div class="bg-red-900/20 border border-red-800 rounded-xl p-6">
      <p class="text-red-400 text-sm">Could not connect: {error}</p>
    </div>
  {:else if info}
    <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
      <h2 class="text-sm font-medium text-gray-500 mb-4">Network Info</h2>
      <dl class="space-y-3">
        <div class="flex justify-between">
          <dt class="text-gray-400">Node ID</dt>
          <dd class="text-gray-200 font-mono text-sm">{info.node_id?.slice(0, 16)}...</dd>
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
        <div class="flex justify-between">
          <dt class="text-gray-400">Ownership Records</dt>
          <dd class="text-gray-200">{info.ownership_count}</dd>
        </div>
        <div class="flex justify-between">
          <dt class="text-gray-400">Protocol Hash</dt>
          <dd class="text-gray-500 font-mono text-xs">{info.version_hash?.slice(0, 24)}...</dd>
        </div>
      </dl>
    </div>
  {/if}
</div>