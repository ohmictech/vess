<script lang="ts">
  import { onMount } from "svelte";
  import { getNodeInfo, type NodeInfo } from "../rpc/client";

  export let asset: "vess" | "bitcoin" | "vichor" = "vess";

  let info: NodeInfo | null = null;
  let loading = true;
  let error = "";
  let rpcUrl = localStorage.getItem("vess_rpc_url") || "http://127.0.0.1:9821";
  let notificationsOn = localStorage.getItem("vess_notifications") !== "off";
  let hapticsOn = localStorage.getItem("vess_haptics") !== "off";

  $: assetColor = asset === "vess" ? "#5fb5d2" : asset === "vichor" ? "#ccff00" : "#f28e13";
  $: inputClass = "flex-1 rounded-lg px-3 py-2 text-[#1a1a1a] placeholder-[#3d484c] font-mono text-sm focus:outline-none transition-colors";
  $: inputStyle = `background: ${assetColor}18`;

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

  function toggleNotifications() {
    notificationsOn = !notificationsOn;
    localStorage.setItem("vess_notifications", notificationsOn ? "on" : "off");
  }

  function toggleHaptics() {
    hapticsOn = !hapticsOn;
    localStorage.setItem("vess_haptics", hapticsOn ? "on" : "off");
  }
</script>

<div class="space-y-4">
  <h1 class="text-xl font-bold">Settings</h1>

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
  </div>

  <!-- RPC Connection -->
  <div>
    <h2 class="text-sm font-medium text-gray-500 mb-2">RPC Connection</h2>
    <div class="flex gap-2">
      <input bind:value={rpcUrl} class={inputClass} style={inputStyle} />
      <button on:click={saveUrl} class="px-3 py-2 bg-[#252d30] hover:bg-[#323a3e] rounded-lg text-sm transition-colors">
        Save
      </button>
    </div>
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
</div>