<script lang="ts">
  import { registerTag, lookupTag } from "../rpc/client";

  export let asset: "vess" | "bitcoin" | "vichor" = "vess";

  let tag = "";
  let lookupTagName = "";
  let lookupResult = "";
  let registering = false;
  let result = "";
  let error = "";

  $: assetColor = asset === "vess" ? "#5fb5d2" : asset === "vichor" ? "#ccff00" : "#f28e13";
  $: inputClass = "flex-1 rounded-lg px-3 py-2 text-[#1a1a1a] placeholder-[#3d484c] focus:outline-none transition-colors";
  $: inputStyle = `background: ${assetColor}18`;

  async function handleRegister() {
    if (!tag) return;
    registering = true;
    error = "";
    result = "";
    try {
      await registerTag(tag);
      result = `Tag +${tag} registered!`;
      tag = "";
    } catch (e) {
      error = String(e);
    } finally {
      registering = false;
    }
  }

  async function handleLookup() {
    if (!lookupTagName) return;
    try {
      const info = await lookupTag(lookupTagName.replace("+", ""));
      lookupResult = `${info.tag} \u2192 ${info.address}`;
    } catch (e) {
      lookupResult = `Lookup failed: ${e}`;
    }
  }
</script>

<div class="w-full max-w-lg mx-auto">
  <h1 class="text-2xl font-bold mb-6">Tags</h1>

  <!-- Register -->
  <div class="bg-[#1c2224] rounded-xl border border-[#2a3033] p-6 mb-6">
    <h2 class="text-lg font-semibold mb-4">Register Tag</h2>
    <div class="flex gap-2">
      <span class="flex items-center text-gray-500">+</span>
      <input
        bind:value={tag}
        placeholder="alice"
        maxlength="20"
        class={inputClass}
        style={inputStyle}
      />
      <button
        on:click={handleRegister}
        disabled={registering || !tag}
        class="px-4 py-2 bg-[#5fb5d2] hover:bg-[#4a9db8] text-black rounded-lg font-medium transition-colors disabled:opacity-50"
      >
        {registering ? "Mining PoW..." : "Register"}
      </button>
    </div>
    <p class="text-xs text-gray-600 mt-2">Lowercase alphanumeric, 3\u201320 chars \u2022 Requires Argon2id PoW \u2022 Permanent once hardened</p>
    {#if result}
      <div class="mt-3 bg-green-900/20 border border-green-800 rounded-lg p-3 text-green-400 text-sm">{result}</div>
    {/if}
    {#if error}
      <div class="mt-3 bg-red-900/20 border border-red-800 rounded-lg p-3 text-red-400 text-sm">{error}</div>
    {/if}
  </div>

  <!-- Lookup -->
  <div class="bg-[#1c2224] rounded-xl border border-[#2a3033] p-6">
    <h2 class="text-lg font-semibold mb-4">Lookup Tag</h2>
    <div class="flex gap-2">
      <input
        bind:value={lookupTagName}
        placeholder="+ALICE"
        class={inputClass}
        style={inputStyle}
      />
      <button on:click={handleLookup} class="px-4 py-2 bg-[#252d30] hover:bg-[#323a3e] rounded-lg font-medium transition-colors">
        Lookup
      </button>
    </div>
    {#if lookupResult}
      <p class="mt-3 text-sm text-gray-300">{lookupResult}</p>
    {/if}
  </div>
</div>