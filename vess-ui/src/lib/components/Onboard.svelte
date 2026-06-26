<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import { walletStatus, checkTag, createWallet, recoverWallet } from "../rpc/client";

  const dispatch = createEventDispatcher();

  type Step = "detect" | "choose" | "new-tag" | "new-seed" | "new-confirm" | "import" | "import-tag" | "done";

  let step: Step = "detect";
  let vesstag = "";
  let seedWords: string[] = [];
  let confirmWords: string[] = Array(12).fill("");
  let loading = false;
  let error = "";
  let tagAvailable = false;

  // Detect existing wallet
  async function detect() {
    loading = true;
    try {
      const status = await walletStatus();
      if (status.exists) {
        dispatch("ready");
        return;
      }
      step = "choose";
    } catch {
      // node offline — still allow onboarding
      step = "choose";
    } finally {
      loading = false;
    }
  }
  detect();

  // Validate tag format
  function validateTag(t: string): string {
    const clean = t.replace(/^\+/, "").toLowerCase();
    if (clean.length < 2) return "too short";
    if (clean.length > 20) return "too long";
    if (!/^[a-zA-Z][a-zA-Z0-9]*$/.test(clean)) return "must start with letter, then letters/numbers";
    return "";
  }

  // Step: new-tag — choose a vesstag
  async function checkTagAvail() {
    error = "";
    const v = validateTag(vesstag);
    if (v) { error = v; return; }
    loading = true;
    try {
      const res = await checkTag(vesstag.replace(/^\+/, "").toLowerCase());
      tagAvailable = res.available;
      if (!res.available) error = res.reason || "tag already taken";
    } catch {
      // assume available if node offline
      tagAvailable = true;
    } finally {
      loading = false;
    }
  }

  async function createNew() {
    error = "";
    if (!tagAvailable) return;
    loading = true;
    try {
      const res = await createWallet(vesstag.replace(/^\+/, "").toLowerCase());
      seedWords = res.phrase;
      step = "new-seed";
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  // Step: new-confirm — verify seed phrase
  function confirmWord(index: number, value: string) {
    confirmWords[index] = value.trim().toLowerCase();
    confirmWords = [...confirmWords];
  }

  function verifySeed(): boolean {
    if (confirmWords.length !== seedWords.length) return false;
    return confirmWords.every((w, i) => w === seedWords[i]);
  }

  function finishNew() {
    if (!verifySeed()) {
      error = "words don't match — try again";
      return;
    }
    step = "done";
    dispatch("ready");
  }

  // Step: import — recover from phrase
  let importPhrase = "";
  async function doRecover() {
    error = "";
    const words = importPhrase.trim().toLowerCase().split(/\s+/);
    if (words.length !== 12) {
      error = "enter exactly 12 words separated by spaces";
      return;
    }
    loading = true;
    try {
      await recoverWallet(words, vesstag.replace(/^\+/, "").toLowerCase());
      step = "done";
      dispatch("ready");
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }
</script>

<div class="flex flex-col items-center justify-center gap-6 max-w-sm mx-auto py-8 px-4 text-center h-dvh">
  <!-- ── Detect (loading) ── -->
  {#if step === "detect"}
    <svg class="w-10 h-10 animate-spin text-[#88cddf]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke-opacity="0.2"/><path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/></svg>
    <p class="text-sm text-gray-400">checking wallet...</p>

  <!-- ── Choose: Create or Import ── -->
  {:else if step === "choose"}
    <h1 class="text-2xl font-bold flex items-center justify-center gap-2" style="color: #88cddf">
      welcome to <img src="/vessicon.png" alt="Vess" class="w-8 h-8 inline-block" />
    </h1>
    <div class="flex flex-col gap-3 w-full">
      <button on:click={() => step = "new-tag"}
        class="w-full py-4 rounded-xl font-semibold text-lg transition-all hover:scale-[1.02] active:scale-[0.98]"
        style="background: #88cddf; color: #1a1a1a;">
        new wallet
      </button>
      <button on:click={() => step = "import"}
        class="w-full py-4 rounded-xl font-semibold text-lg transition-all hover:scale-[1.02] active:scale-[0.98]"
        style="background: #88cddf18; color: #88cddf; border: 2px solid #88cddf40;">
        import from seed
      </button>
    </div>

  <!-- ── New: Choose vesstag ── -->
  {:else if step === "new-tag"}
    <h1 class="text-xl font-bold" style="color: #88cddf">Choose Your VessTag</h1>
    <p class="text-sm text-gray-400">This is your unique name on the Vess network. It's how you receive payments.</p>
    <div class="w-full space-y-3">
      <div class="relative">
        <span class="absolute left-4 top-1/2 -translate-y-1/2 text-xl font-bold pointer-events-none" style="color: #88cddf">+</span>
        <input
          bind:value={vesstag}
          on:input={checkTagAvail}
          placeholder="ALICE"
          class="w-full rounded-xl pl-10 pr-10 py-3 text-xl text-center uppercase bg-[#88cddf]12 text-[#88cddf] placeholder-[#88cddf]/30 focus:outline-none"
          style="background: #88cddf18"
        />
      </div>
      {#if tagAvailable}
        <p class="text-xs text-green-400">✓ tag available</p>
      {:else if vesstag.length >= 2}
        <p class="text-xs text-red-400">{error || "checking..."}</p>
      {/if}
      <button on:click={createNew} disabled={loading || !tagAvailable}
        class="w-full py-3 rounded-xl font-semibold transition-all disabled:opacity-40"
        style="background: #88cddf; color: #1a1a1a;">
        {loading ? "creating..." : "create wallet"}
      </button>
      <button on:click={() => step = "choose"}
        class="text-xs text-gray-500 hover:text-gray-300 transition-colors">← back</button>
    </div>

  <!-- ── New: Show seed phrase ── -->
  {:else if step === "new-seed"}
    <h1 class="text-xl font-bold" style="color: #f28e13">Write Down Your Recovery Phrase</h1>
    <p class="text-xs text-gray-400">These 12 words are the ONLY way to recover your wallet. Never share them.</p>
    <div class="grid grid-cols-3 gap-2 w-full bg-[#1a1a1a] rounded-xl p-4 border border-[#f28e13]/30">
      {#each seedWords as word, i}
        <div class="flex items-center gap-1.5 text-xs">
          <span class="text-gray-600 w-5 text-right">{i + 1}.</span>
          <span class="font-mono text-gray-200">{word}</span>
        </div>
      {/each}
    </div>
    <button on:click={() => { confirmWords = Array(12).fill(""); step = "new-confirm"; }}
      class="w-full py-3 rounded-xl font-semibold transition-all"
      style="background: #f28e13; color: #1a1a1a;">
      i've written them down
    </button>

  <!-- ── New: Confirm seed phrase ── -->
  {:else if step === "new-confirm"}
    <h1 class="text-xl font-bold" style="color: #f28e13">Confirm Your Phrase</h1>
    <p class="text-xs text-gray-400">enter each word to verify</p>
    <div class="grid grid-cols-3 gap-2 w-full">
      {#each seedWords as _, i}
        <div class="flex flex-col gap-0.5">
          <span class="text-xs text-gray-600">{i + 1}.</span>
          <input
            value={confirmWords[i] || ""}
            on:input={(e) => confirmWord(i, (e.target as HTMLInputElement).value)}
            placeholder="..."
            class="rounded-lg px-2 py-2 text-sm text-center bg-[#1a1a1a] text-gray-200 border border-[#323a3e] focus:outline-none focus:border-[#f28e13] transition-colors"
          />
        </div>
      {/each}
    </div>
    {#if error}
      <p class="text-xs text-red-400">{error}</p>
    {/if}
    <button on:click={finishNew}
      class="w-full py-3 rounded-xl font-semibold transition-all"
      style="background: #f28e13; color: #1a1a1a;">
      Confirm &amp; Finish
    </button>
    <button on:click={() => step = "new-seed"}
      class="text-xs text-gray-500 hover:text-gray-300 transition-colors">← view phrase again</button>

  <!-- ── Import: Enter 12 words ── -->
  {:else if step === "import"}
    <h1 class="text-xl font-bold" style="color: #88cddf">Recover Wallet</h1>
    <p class="text-sm text-gray-400">enter your 12-word recovery phrase</p>
    <textarea
      bind:value={importPhrase}
      placeholder="word1 word2 word3 ... word12"
      rows="3"
      class="w-full rounded-xl px-4 py-3 text-sm bg-[#88cddf]12 text-gray-200 placeholder-[#88cddf]/30 focus:outline-none resize-none"
      style="background: #88cddf18"
    ></textarea>
    {#if error}
      <p class="text-xs text-red-400">{error}</p>
    {/if}
    <button on:click={() => { error = ""; step = "import-tag"; }}
      disabled={importPhrase.trim().split(/\s+/).length !== 12}
      class="w-full py-3 rounded-xl font-semibold transition-all disabled:opacity-40"
      style="background: #88cddf; color: #1a1a1a;">
      Continue
    </button>
    <button on:click={() => step = "choose"}
      class="text-xs text-gray-500 hover:text-gray-300 transition-colors">← back</button>

  <!-- ── Import: Choose/confirm tag ── -->
  {:else if step === "import-tag"}
    <h1 class="text-xl font-bold" style="color: #88cddf">Confirm Your VessTag</h1>
    <p class="text-sm text-gray-400">Enter the tag associated with this wallet.</p>
    <div class="relative">
      <span class="absolute left-4 top-1/2 -translate-y-1/2 text-xl font-bold pointer-events-none" style="color: #88cddf">+</span>
      <input
        bind:value={vesstag}
        placeholder="ALICE"
        class="w-full rounded-xl pl-10 pr-10 py-3 text-xl text-center uppercase bg-[#88cddf]12 text-[#88cddf] placeholder-[#88cddf]/30 focus:outline-none"
        style="background: #88cddf18"
      />
    </div>
    {#if error}
      <p class="text-xs text-red-400">{error}</p>
    {/if}
    <button on:click={doRecover} disabled={loading || vesstag.length < 2}
      class="w-full py-3 rounded-xl font-semibold transition-all disabled:opacity-40"
      style="background: #88cddf; color: #1a1a1a;">
      {loading ? "recovering..." : "Recover Wallet"}
    </button>
    <button on:click={() => step = "import"}
      class="text-xs text-gray-500 hover:text-gray-300 transition-colors">← back</button>

  <!-- ── Done ── -->
  {:else if step === "done"}
    <div class="w-16 h-16 rounded-full flex items-center justify-center" style="background: #10b98120">
      <svg class="w-8 h-8 text-[#10b981]" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </div>
    <h1 class="text-xl font-bold text-[#10b981]">Wallet Ready</h1>
    <p class="text-sm text-gray-400">Your wallet is set up and connected.</p>
  {/if}
</div>
