<script lang="ts">
  import Dashboard from "./lib/components/Dashboard.svelte";
  import SendPanel from "./lib/components/SendPanel.svelte";
  import ReceivePanel from "./lib/components/ReceivePanel.svelte";
  import TagsPanel from "./lib/components/TagsPanel.svelte";
  import NodeStatus from "./lib/components/NodeStatus.svelte";
  import MintPanel from "./lib/components/MintPanel.svelte";

  type Tab = "dashboard" | "send" | "receive" | "tags" | "mint" | "node";

  let activeTab: Tab = "dashboard";
  let sidebarOpen = false;

  function onNavigate(tab: Tab) {
    activeTab = tab;
    sidebarOpen = false;
  }

  const tabs = [
    { id: "dashboard" as Tab, label: "Dashboard", icon: "🏠", short: "Home" },
    { id: "send" as Tab, label: "Send", icon: "📤", short: "Send" },
    { id: "receive" as Tab, label: "Receive", icon: "📥", short: "Recv" },
    { id: "tags" as Tab, label: "Tags", icon: "🏷️", short: "Tags" },
    { id: "mint" as Tab, label: "Time-Lock Mint", icon: "🔒", short: "Mint" },
    { id: "node" as Tab, label: "Node", icon: "🌐", short: "Node" },
  ] as const;
</script>

<svelte:window on:resize={() => sidebarOpen = false} />

<div class="flex flex-col md:flex-row h-dvh overflow-hidden bg-gray-950">
  <!-- Mobile header bar -->
  <header class="md:hidden flex items-center justify-between px-4 py-3 bg-gray-900 border-b border-gray-800 shrink-0">
    <button
      on:click={() => sidebarOpen = !sidebarOpen}
      class="p-2 -ml-2 rounded-lg hover:bg-gray-800 transition-colors"
      aria-label="Menu"
    >
      <svg class="w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
      </svg>
    </button>
    <div class="flex items-center gap-2">
      <span class="text-amber-400 text-xl">◆</span>
      <span class="text-white font-bold">Vess</span>
    </div>
    <div class="w-10" /> <!-- spacer for centering -->
  </header>

  <!-- Desktop sidebar + Mobile overlay sidebar -->
  <aside
    class="fixed inset-y-0 left-0 z-40 w-64 bg-gray-900 border-r border-gray-800 flex flex-col p-4 transition-transform duration-200 md:static md:translate-x-0"
    class:-translate-x-full={!sidebarOpen}
    class:translate-x-0={sidebarOpen}
  >
    <!-- Close button - mobile only -->
    <button
      on:click={() => sidebarOpen = false}
      class="md:hidden self-end p-1 mb-2 rounded-lg hover:bg-gray-800 transition-colors"
      aria-label="Close menu"
    >
      <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
      </svg>
    </button>

    <div class="text-xl font-bold mb-8 flex items-center gap-2">
      <span class="text-amber-400 text-2xl">◆</span>
      <span class="text-white">Vess</span>
    </div>

    <nav class="flex flex-col gap-1 flex-1">
      {#each tabs as item}
        <button
          class="flex items-center gap-3 px-4 py-2.5 rounded-lg text-left transition-colors"
          class:text-amber-400={activeTab === item.id}
          class:bg-gray-800={activeTab === item.id}
          class:text-gray-400={activeTab !== item.id}
          class:hover:bg-gray-800={activeTab !== item.id}
          on:click={() => onNavigate(item.id)}
        >
          <span class="text-lg">{item.icon}</span>
          <span class="font-medium">{item.label}</span>
        </button>
      {/each}
    </nav>

    <div class="text-xs text-gray-600 mt-4 border-t border-gray-800 pt-4 hidden md:block">
      Vess Protocol &mdash; CLTV Time-Credit
    </div>
  </aside>

  <!-- Mobile overlay backdrop -->
  {#if sidebarOpen}
    <div
      class="fixed inset-0 z-30 bg-black/50 md:hidden"
      on:click={() => sidebarOpen = false}
      on:keydown={(e) => e.key === 'Escape' && (sidebarOpen = false)}
      role="button"
      tabindex="0"
    />
  {/if}

  <!-- Main content -->
  <main class="flex-1 overflow-y-auto p-4 md:p-6 pb-20 md:pb-6">
    {#if activeTab === "dashboard"}
      <Dashboard />
    {:else if activeTab === "send"}
      <SendPanel />
    {:else if activeTab === "receive"}
      <ReceivePanel />
    {:else if activeTab === "tags"}
      <TagsPanel />
    {:else if activeTab === "mint"}
      <MintPanel />
    {:else if activeTab === "node"}
      <NodeStatus />
    {/if}
  </main>

  <!-- Mobile bottom tab bar -->
  <nav class="md:hidden fixed bottom-0 inset-x-0 z-40 bg-gray-900 border-t border-gray-800 flex justify-around items-center px-2 py-1.5 safe-area-bottom">
    {#each tabs as item}
      <button
        class="flex flex-col items-center gap-0.5 py-1 px-2 rounded-lg min-w-0 flex-1 transition-colors"
        class:text-amber-400={activeTab === item.id}
        class:text-gray-500={activeTab !== item.id}
        on:click={() => onNavigate(item.id)}
      >
        <span class="text-lg">{item.icon}</span>
        <span class="text-[10px] font-medium leading-tight">{item.short}</span>
      </button>
    {/each}
  </nav>
</div>

