<script lang="ts">
  import { onMount } from "svelte";
  import { getBalance, getVessTag, type BalanceData } from "../rpc/client";

  // ── Types ──────────────────────────────────────────────
  type Asset = "vess" | "bitcoin" | "vichor";
  type Mode = "idle" | "pressed" | "dragging";
  type ActionId = "send" | "add" | "mint" | "settings";

  interface AssetInfo {
    label: string;
    color: string;
    glow: string;
    icon: string;
    ticker: string;
  }

  interface HexItem {
    id: Asset | ActionId;
    label: string;
    color: string;
    glow: string;
    icon: string;
    isAsset: boolean;
    isCenter: boolean;
  }

  // ── RPC data ──────────────────────────────────────────
  let balance: BalanceData | null = null;
  let vesstag = "";

  onMount(async () => {
    try { balance = await getBalance(); } catch { /* node offline */ }
    try { vesstag = await getVessTag(); } catch { /* not set yet */ }
    window.addEventListener("vesstag-set", (e: Event) => {
      vesstag = (e as CustomEvent).detail;
    });
  });

  // ── State ─────────────────────────────────────────────
  export let selectedAsset: Asset = "vess";
  let mode: Mode = "idle";
  let dragTarget: number | null = null;

  const ASSETS: Record<Asset, AssetInfo> = {
    vess:   { label: "Vess",    color: "#88cddf", glow: "rgba(136,205,223,0.35)",   icon: "/vessicon.png",    ticker: "/vessicon.png" },
    bitcoin:{ label: "Bitcoin", color: "#f28e13", glow: "rgba(242,142,19,0.35)",   icon: "/bitcoinicon.png", ticker: "/saticon.png" },
    vichor: { label: "Vichor",  color: "#ccff00", glow: "rgba(204,255,0,0.35)",    icon: "/vichoricon.png",  ticker: "/vichoricon.png" },
  };

  const ACTION_COLORS: Record<ActionId, string> = {
    send:     "#3b82f6",
    add:      "#10b981",
    mint:     "#eab308",
    settings: "#6b7280",
  };

  // ── Hexagon geometry (pointy-top) ─────────────────────
  const R = 42;                         // hex radius in SVG units
  const SQRT3 = Math.sqrt(3);
  const SPACING = 1.1;                  // gap multiplier between hexagons
  const CENTER = { x: 0, y: 112 };      // ~26% from viewBox bottom

  // Pre-compute 6 neighbor offsets (axial coords → pixel)
  const NEIGHBOR_AXIAL = [
    { q: 1, r: 0  },  // 1: right  — Send
    { q: 1, r: -1 },  // 2: top-right — Add
    { q: 0, r: -1 },  // 3: top-left — Swap
    { q:-1, r: 0  },  // 4: left — Settings
    { q:-1, r: 1  },  // 5: bottom-left — Asset A
    { q: 0, r: 1  },  // 6: bottom-right — Asset B
  ];

  function axialToPixel(q: number, r: number) {
    return {
      x: CENTER.x + SQRT3 * (q + r / 2) * R * SPACING,
      y: CENTER.y + 1.5 * r * R * SPACING,
    };
  }

  const NEIGHBOR_PX = NEIGHBOR_AXIAL.map(({ q, r }) => axialToPixel(q, r));
  const ALL_POSITIONS = [CENTER, ...NEIGHBOR_PX];

  // Push a position radially outward from center by a given amount
  function pushOut(pos: { x: number; y: number }, amount: number) {
    const dx = pos.x - CENTER.x;
    const dy = pos.y - CENTER.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist < 0.01) return { x: pos.x, y: pos.y };
    const factor = 1 + amount / dist;
    return {
      x: CENTER.x + dx * factor,
      y: CENTER.y + dy * factor,
    };
  }

  // SVG hexagon path (pointy-top, first vertex at top)
  function hexPath(r: number): string {
    const pts: string[] = [];
    for (let i = 0; i < 6; i++) {
      const a = (Math.PI / 180) * (60 * i - 90);
      pts.push(`${(r * Math.cos(a)).toFixed(3)},${(r * Math.sin(a)).toFixed(3)}`);
    }
    return `M${pts.join(" L")} Z`;
  }

  // Per-asset image positioning (multipliers of R)
  const IMG_LAYOUT: Record<Asset, { ox: number; oy: number; w: number; h: number }> = {
    vess:    { ox: -0.54, oy: -0.50, w: 1.08, h: 1.08 },
    bitcoin: { ox: -0.68, oy: -0.70, w: 1.36, h: 1.36 },
    vichor:  { ox: -0.39, oy: -0.34, w: 0.78, h: 0.78 },
  };

  function imgLayout(asset: Asset) {
    const l = IMG_LAYOUT[asset];
    return {
      x: l.ox * R,
      y: l.oy * R,
      w: l.w * R,
      h: l.h * R,
    };
  }

  // Push a position with optional upward bias (for side tooltips)
  function pushUpward(pos: { x: number; y: number }, amount: number, upBias: number = 0) {
    const dx = pos.x - CENTER.x;
    const dy = pos.y - CENTER.y - upBias;  // bias numerator upward
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist < 0.01) return { x: pos.x, y: pos.y - amount };
    const factor = 1 + amount / dist;
    return {
      x: CENTER.x + dx * factor,
      y: CENTER.y + (pos.y - CENTER.y) * factor - upBias * (factor - 1),
    };
  }

  const DARK_ICON = "#1c2224";           // panel navy for icons on asset hexes & action drag targets

  const H = hexPath(R);                 // outer hex path

  // ── Derived: outer assets ─────────────────────────────
  $: otherAssets = (["vess", "bitcoin", "vichor"] as Asset[]).filter(a => a !== selectedAsset);

  // ── Build hex item for each grid position ─────────────
  $: items = ALL_POSITIONS.map((pos, i): HexItem => {
    if (i === 0) {
      // Center — current selected asset
      const a = ASSETS[selectedAsset];
      return { id: selectedAsset, label: a.label, color: a.color, glow: a.glow, icon: a.icon, isAsset: true, isCenter: true };
    }
    switch (i) {
      case 1: return { id: "send",  label: "Send",  color: ACTION_COLORS.send,  glow: "rgba(59,130,246,0.3)",  icon: "➤", isAsset: false, isCenter: false };
      case 2: return { id: "add",   label: "Receive", color: ACTION_COLORS.add,   glow: "rgba(16,185,129,0.3)",  icon: "↓", isAsset: false, isCenter: false };
      case 3: return { id: "mint",  label: "Mint",    color: ACTION_COLORS.mint,  glow: "rgba(234,179,8,0.3)",   icon: "+", isAsset: false, isCenter: false };
      case 4: return { id: "settings", label: "Settings", color: ACTION_COLORS.settings, glow: "rgba(107,114,128,0.3)", icon: "⚙", isAsset: false, isCenter: false };
      case 5: {
        const a = ASSETS[otherAssets[0]];
        return { id: otherAssets[0], label: a.label, color: a.color, glow: a.glow, icon: a.icon, isAsset: true, isCenter: false };
      }
      case 6: {
        const a = ASSETS[otherAssets[1]];
        return { id: otherAssets[1], label: a.label, color: a.color, glow: a.glow, icon: a.icon, isAsset: true, isCenter: false };
      }
      default: return { id: "vess", label: "", color: "#000", glow: "", icon: "", isAsset: false, isCenter: false };
    }
  });

  // ── Amount text ───────────────────────────────────────
  $: currentAsset = ASSETS[selectedAsset];

  // ── Haptic feedback on hex hover ──────────────────────
  let prevTarget: number | null = null;
  let centerPressed = false;
  $: if (dragTarget !== null && dragTarget !== prevTarget) {
    navigator.vibrate?.(6);
    prevTarget = dragTarget;
  }
  $: if (dragTarget === null) prevTarget = null;

  // ── Format with suffix ───────────────────────────────
  function fmt(n: number): string {
    if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(n % 1_000_000_000 === 0 ? 0 : 1) + "b";
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(n % 1_000_000 === 0 ? 0 : 1) + "m";
    if (n >= 1_000) return (n / 1_000).toFixed(n % 1_000 === 0 ? 0 : 1) + "k";
    return String(n);
  }

  $: displayAmount = (() => {
    if (!balance) {
      if (selectedAsset === "vess") return fmt(8472);
      if (selectedAsset === "bitcoin") return fmt(2500000);
      if (selectedAsset === "vichor") return fmt(16384);
      return "0";
    }
    switch (selectedAsset) {
      case "vess":    return fmt(balance.balance ?? 0);
      case "bitcoin": return fmt(balance.watch_only_balance ?? 0);
      case "vichor":  return fmt(balance.vichor_balance ?? 0);
    }
  })();

  // ── Pointer handling ──────────────────────────────────
  let svgEl: SVGSVGElement;

  function svgPoint(e: PointerEvent): DOMPoint {
    const pt = svgEl.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    return pt.matrixTransform(svgEl.getScreenCTM()?.inverse());
  }

  function closestHex(pt: DOMPoint): number | null {
    let best = -1;
    let bestDist = Infinity;
    for (let i = 0; i < ALL_POSITIONS.length; i++) {
      const dx = pt.x - ALL_POSITIONS[i].x;
      const dy = pt.y - ALL_POSITIONS[i].y;
      const d = Math.sqrt(dx * dx + dy * dy);
      if (d < R * 1.15 && d < bestDist) { best = i; bestDist = d; }
    }
    return best >= 0 ? best : null;
  }

  function onDown(e: PointerEvent) {
    (e.target as Element)?.setPointerCapture?.(e.pointerId);
    const pt = svgPoint(e);
    const hit = closestHex(pt);
    if (hit === 0) {
      mode = "pressed";
      dragTarget = null;
      centerPressed = true;
      setTimeout(() => centerPressed = false, 150);
    }
  }

  function onMove(e: PointerEvent) {
    if (mode === "idle") return;
    const pt = svgPoint(e);
    const hit = closestHex(pt);
    if (hit !== null && hit !== 0) {
      mode = "dragging";
      dragTarget = hit;
    } else if (hit === 0) {
      mode = "pressed";
      dragTarget = null;
    }
  }

  function onUp(_e: PointerEvent) {
    if (mode === "dragging" && dragTarget !== null) {
      commitAction(dragTarget);
    }
    mode = "idle";
    dragTarget = null;
  }

  // ── Action dispatch ───────────────────────────────────
  export let onNavigate: (tab: string) => void = () => {};

  function commitAction(targetIdx: number) {
    const item = items[targetIdx];
    if (!item) return;

    if (item.isAsset && !item.isCenter) {
      // Swap: set selectedAsset to that asset
      selectedAsset = item.id as Asset;
    } else if (!item.isAsset) {
      // Action
      switch (item.id) {
        case "send":     onNavigate("send"); break;
        case "add":
          if (selectedAsset === "bitcoin") onNavigate("bitcoin_receive");
          else onNavigate("receive");
          break;
        case "mint":
          if (selectedAsset === "bitcoin") onNavigate("buy_btc");
          else if (selectedAsset === "vichor") onNavigate("buy_vichor");
          else onNavigate("mint");
          break;
        case "settings": onNavigate("node"); break;
      }
    }
  }
</script>

<svelte:window
  on:pointerup={() => { mode = "idle"; dragTarget = null; }}
  on:pointercancel={() => { mode = "idle"; dragTarget = null; }}
/>

<div class="hex-root">
  <!-- Amount readout — 25% from top, visible only when active -->
  <div
    class="amount-readout"
    class:visible={mode !== "idle"}
    style="color: {currentAsset.color}; text-shadow: 0 0 32px {currentAsset.glow}"
  >
    <div class="amount-row">
      <div
        class="amount-ticker"
        class:amount-ticker-sm={selectedAsset === "vichor"}
        class:amount-ticker-down={selectedAsset === "vess" || selectedAsset === "bitcoin"}
        style="mask-image: url({currentAsset.ticker}); -webkit-mask-image: url({currentAsset.ticker})"
      ></div>
      <span class="amount-value">{displayAmount}</span>
    </div>
  </div>

  <!-- SVG hexagonal grid -->
  <svg
    bind:this={svgEl}
    class="hex-svg"
    viewBox="-160 -220 320 500"
    preserveAspectRatio="xMidYMid meet"
    on:pointerdown={onDown}
    on:pointermove={onMove}
    on:pointerup={onUp}
    style="touch-action:none"
    role="application"
    aria-label="Hexagonal wallet control panel"
  >
    <defs>
      <!-- Glow filter for outer hexagons -->
      <filter id="hexGlow" x="-60%" y="-60%" width="220%" height="220%">
        <feGaussianBlur in="SourceGraphic" stdDeviation="2.5" />
      </filter>
      <!-- Glow filter for center hex -->
      <filter id="centerGlow" x="-80%" y="-80%" width="260%" height="260%">
        <feGaussianBlur in="SourceGraphic" stdDeviation="6" result="blur" />
      </filter>
      <!-- Lighter glow for tooltip text -->
      <filter id="textGlow" x="-40%" y="-40%" width="180%" height="180%">
        <feGaussianBlur in="SourceGraphic" stdDeviation="0.3" />
      </filter>
      <!-- Subtle noise texture for sci-fi feel -->
      <filter id="noise">
        <feTurbulence type="fractalNoise" baseFrequency="0.65" numOctaves="3" stitchTiles="stitch" />
        <feColorMatrix type="saturate" values="0" />
        <feBlend in="SourceGraphic" mode="multiply" result="n" />
      </filter>
      <!-- Radial gradient for center hex -->
      <radialGradient id="centerGrad" cx="50%" cy="40%" r="55%">
        <stop offset="0%" stop-color="currentColor" stop-opacity="0.22" />
        <stop offset="100%" stop-color="currentColor" stop-opacity="0.04" />
      </radialGradient>
      <!-- Shimmer sweep for asset hexagon drag target -->
      <linearGradient id="shimmer" x1="-1" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="white" stop-opacity="0" />
        <stop offset="35%" stop-color="white" stop-opacity="0" />
        <stop offset="50%" stop-color="white" stop-opacity="0.5" />
        <stop offset="65%" stop-color="white" stop-opacity="0" />
        <stop offset="100%" stop-color="white" stop-opacity="0" />
        <animate attributeName="x1" values="-1;2" dur="1.1s" repeatCount="indefinite" />
        <animate attributeName="x2" values="0;3" dur="1.1s" repeatCount="indefinite" />
      </linearGradient>
    </defs>

    <!-- Subtle grid lines (sci-fi background) -->
    <g opacity="0.06">
      <line x1="-200" y1="0" x2="200" y2="0" stroke="currentColor" stroke-width="0.3" />
      <line x1="0" y1="-200" x2="0" y2="200" stroke="currentColor" stroke-width="0.3" />
      <circle cx="0" cy={CENTER.y} r={R * SPACING * 1.9} fill="none" stroke="currentColor" stroke-width="0.3" stroke-dasharray="3 6" />
    </g>

    <!-- Outer hexagons — render first (behind center), float out on press -->
    {#each items.slice(1) as item, idx}
      {@const i = idx + 1}
      {@const pos = ALL_POSITIONS[i]}
      {@const isTarget = mode === "dragging" && dragTarget === i}
      {@const targetOuterIdx = dragTarget !== null ? dragTarget - 1 : -1}
      {@const isAdjacent = dragTarget !== null && !isTarget && (
        idx === (targetOuterIdx - 1 + 6) % 6 || idx === (targetOuterIdx + 1) % 6
      )}
      {@const pushedPos = isTarget ? pushOut(pos, 8) : isAdjacent ? pushOut(pos, 4) : pos}
      {@const pushDx = pushedPos.x - pos.x}
      {@const pushDy = pushedPos.y - pos.y}
      {@const tooltipPos = !isTarget ? { x: 0, y: 0 } :
        idx === 0 ? pushUpward(pos, R + 24, 170) :  // Send — tuck upward & inward
        idx === 3 ? pushUpward(pos, R + 24, 170) :  // Settings — tuck upward & inward
        pushOut(pos, R + 24)}
      {@const assetFill = item.isAsset ? item.color : "transparent"}
      {@const assetFillOpacity = item.isAsset ? 0.9 : 0}
      {@const iconColor = item.isAsset ? DARK_ICON : (isTarget ? DARK_ICON : item.color)}

      <g
        class="hex-float-wrapper"
        class:hex-floated={mode !== "idle"}
        style="transform-origin: {CENTER.x}px {CENTER.y}px"
      >
        <g
          transform="translate({pos.x.toFixed(2)},{pos.y.toFixed(2)})"
          class="hex-group"
          style="color: {item.color}"
        >
          <g
            class="hex-scale"
            class:hex-bumped={isTarget || isAdjacent}
            class:hex-target={isTarget}
            style="--push-x: {pushDx.toFixed(1)}; --push-y: {pushDy.toFixed(1)}; --scale: {isTarget ? 1.08 : 1}"
          >
          <!-- Hex background fill (solid for assets, subtle for actions) -->
          <path
            d={H}
            fill={assetFill}
            opacity={assetFillOpacity}
            class="hex-fill-solid"
          />

          <!-- Hex border -->
          <path
            d={H}
            fill="none"
            stroke="currentColor"
            stroke-width={item.isAsset ? 1.5 : 1.2}
            opacity={item.isAsset ? 1 : 0.5}
            class="hex-border"
          />

          <!-- Action hex: subtle fill normally, solid fill on drag target -->
          {#if !item.isAsset}
            <path
              d={H}
              fill="currentColor"
              opacity={isTarget ? 0.88 : 0.05}
              class="hex-fill"
            />
          {/if}

          <!-- Asset hex: shimmer sweep on drag target -->
          {#if item.isAsset && isTarget}
            <path
              d={H}
              fill="url(#shimmer)"
              opacity="1"
              class="hex-shimmer"
            />
          {/if}

          <!-- Energy beam from center to drag target -->
          {#if isTarget}
            {@const bdx = CENTER.x - pos.x}
            {@const bdy = CENTER.y - pos.y}
            {@const bdist = Math.sqrt(bdx * bdx + bdy * bdy)}
            {@const bnx = -bdy / bdist}
            {@const bny = bdx / bdist}
            {@const cw = R * 0.55}
            {@const hw = R * 0.2}
            <defs>
              <linearGradient id="beam-{i}" x1="{bdx}" y1="{bdy}" x2="0" y2="0" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stop-color={ASSETS[selectedAsset].color} stop-opacity="0.5" />
                <stop offset="50%" stop-color={item.color} stop-opacity="0.4" />
                <stop offset="100%" stop-color={item.color} stop-opacity="0.08" />
              </linearGradient>
            </defs>
            <path
              d="M{bdx + bnx * cw},{bdy + bny * cw} L{bnx * hw},{bny * hw} L{-bnx * hw},{-bny * hw} L{bdx - bnx * cw},{bdy - bny * cw} Z"
              fill="url(#beam-{i})"
              filter="url(#centerGlow)"
            />
          {/if}

          <!-- Glow ring -->
          <path
            d={H}
            fill="none"
            stroke="currentColor"
            stroke-width="2.5"
            opacity={isTarget ? 0.7 : 0}
            filter="url(#hexGlow)"
            class="hex-glow-ring"
          />

          <!-- Icon -->
          {#if item.isAsset}
            {@const il = imgLayout(item.id as Asset)}
            <image
              href={item.icon}
              x={il.x.toFixed(1)}
              y={il.y.toFixed(1)}
              width={il.w.toFixed(1)}
              height={il.h.toFixed(1)}
              class="hex-icon-img"
            />
          {:else}
            <text
              x="0"
              y="0"
              text-anchor="middle"
              dominant-baseline="central"
              class="hex-icon-text"
              class:hex-icon-text-sm={item.id === "send"}
              class:hex-icon-text-xs={item.id === "settings"}
              class:hex-icon-text-sm2={item.id === "add"}
              class:hex-icon-text-up={item.id === "mint"}
              fill={iconColor}
              opacity="0.85"
            >{item.icon}</text>
          {/if}

          <!-- Tooltip label on drag target -->
          {#if isTarget}
            <text
              x={tooltipPos.x - pos.x}
              y={tooltipPos.y - pos.y}
              text-anchor="middle"
              dominant-baseline="central"
              class="hex-tooltip"
              fill="currentColor"
            >{item.label}</text>
          {/if}
        </g>
        </g>
      </g>
    {/each}

    <!-- Center hexagon — rendered last (on top) -->
    {#if true}
      {@const centerItem = items[0]}
      {@const centerPos = ALL_POSITIONS[0]}
    <g
      transform="translate({centerPos.x.toFixed(2)},{centerPos.y.toFixed(2)})"
      style="color: {centerItem.color}"
    >
      <!-- Chromatic aberration wobble — red channel -->
      <path
        d={H}
        fill="rgba(255,60,60,0.22)"
      >
        <animateTransform attributeName="transform" type="translate" values="-3,-2;4,3;-5,-1;2,5;-4,-3;5,-2;-2,4;-3,-2" dur="0.35s" repeatCount="indefinite" />
      </path>

      <!-- Chromatic aberration wobble — blue channel -->
      <path
        d={H}
        fill="rgba(40,120,255,0.22)"
      >
        <animateTransform attributeName="transform" type="translate" values="3,2;-4,-3;5,1;-2,-5;4,3;-5,2;2,-4;3,2" dur="0.38s" repeatCount="indefinite" />
      </path>

      <!-- Animated glow layer behind hex -->
      <path
        d={H}
        fill="currentColor"
        opacity="0"
        filter="url(#centerGlow)"
      >
        <animate attributeName="opacity" values="0.15;0.55;0.15" dur="2.5s" repeatCount="indefinite" />
      </path>

      <g class="hex-group hex-center" class:hex-press={centerPressed}>
      <!-- Hex background fill -->
      <path
        d={H}
        fill={centerItem.color}
        opacity="0.9"
        class="hex-fill-solid"
      />

      <!-- Hex border -->
      <path
        d={H}
        fill="none"
        stroke="currentColor"
        stroke-width="1.5"
        opacity="1"
        class="hex-border"
      />

      <!-- Radial gradient overlay -->
      <path d={H} fill="url(#centerGrad)" />

      <!-- Icon -->
      {#if centerItem.isAsset}
        {@const il = imgLayout(centerItem.id as Asset)}
        <image
          href={centerItem.icon}
          x={il.x.toFixed(1)}
          y={il.y.toFixed(1)}
          width={il.w.toFixed(1)}
          height={il.h.toFixed(1)}
          class="hex-icon-img"
        />
      {:else}
        <text
          x="0"
          y="0"
          text-anchor="middle"
          dominant-baseline="central"
          class="hex-icon-text hex-icon-text-lg"
          fill={DARK_ICON}
        >{centerItem.icon}</text>
      {/if}
    </g>
    </g>
    {/if}
  </svg>

  <!-- Hint text at bottom (idle only) -->
  <div class="hint-text" class:visible={mode === "idle"}>
    hold to navigate
  </div>

  <!-- Wallet tag — bottom-left, visible on press -->
  <div
    class="wallet-tag tag-case"
    class:visible={mode !== "idle"}
    style="color: {currentAsset.color}"
  >
    {vesstag}
  </div>
</div>

<style>
  .hex-root {
    position: relative;
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
  }

  .hex-svg {
    width: 100%;
    height: 100%;
    color: #2a3033;
  }

  /* ── Amount readout ─────────────────────────────── */
  .amount-readout {
    position: absolute;
    top: 25%;
    left: 50%;
    transform: translate(-50%, -50%);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    opacity: 0;
    transition: opacity 0.25s ease;
    pointer-events: none;
    z-index: 10;
  }
  .amount-readout.visible {
    opacity: 1;
  }
  .amount-row {
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .amount-ticker {
    width: 26px;
    height: 26px;
    background: currentColor;
    mask-size: contain;
    mask-repeat: no-repeat;
    -webkit-mask-size: contain;
    -webkit-mask-repeat: no-repeat;
    filter: drop-shadow(0 0 12px currentColor);
    margin-right: -2px;
    transform: translateX(3px);
  }
  .amount-ticker-sm {
    width: 18px;
    height: 18px;
    transform: translateX(2px) translateY(3px);
  }
  .amount-ticker-down {
    transform: translateX(3px) translateY(1px);
  }
  .amount-value {
    font-size: 46px;
    font-weight: 300;
    letter-spacing: 0.08em;
    font-variant-numeric: tabular-nums;
    font-family: "Orbitron", "Inter", "SF Mono", monospace;
  }

  /* ── Float-out wrapper (outer hexagons) ─────────────── */
  .hex-float-wrapper {
    transform: scale(0);
    transform-box: view-box;
    opacity: 0;
    pointer-events: none;
  }
  .hex-float-wrapper.hex-floated {
    transform: scale(1);
    opacity: 1;
    pointer-events: auto;
    animation: floatBounce 0.28s ease-out forwards;
  }

  @keyframes floatBounce {
    0%   { transform: scale(0); opacity: 0; }
    60%  { transform: scale(1.04); opacity: 1; }
    85%  { transform: scale(0.97); }
    100% { transform: scale(1); opacity: 1; }
  }

  /* ── Hex groups ─────────────────────────────────── */
  .hex-group {
    transition: opacity 0.3s ease;
    cursor: pointer;
  }

  /* Scale wrapper for hover push-out (animated via CSS vars) */
  .hex-scale {
    transform: translate(calc(var(--push-x, 0) * 1px), calc(var(--push-y, 0) * 1px)) scale(var(--scale, 1));
    transition: transform 0.28s cubic-bezier(0.34, 1.56, 0.64, 1);
  }

  /* Target highlight */
  .hex-target .hex-border {
    opacity: 1 !important;
  }
  .hex-target .hex-fill {
    opacity: 0.18 !important;
  }
  .hex-target .hex-fill-solid {
    opacity: 1 !important;
  }
  .hex-target .hex-glow-ring {
    opacity: 0.8 !important;
  }

  /* ── Sub-elements ───────────────────────────────── */
  .hex-border,
  .hex-fill,
  .hex-fill-solid,
  .hex-glow-ring,
  .hex-shimmer {
    transition: opacity 0.2s ease, stroke 0.3s ease, fill 0.3s ease;
  }

  .hex-icon-text {
    font-size: 48px;
    transition: opacity 0.2s ease, fill 0.25s ease;
  }
  .hex-icon-text-sm {
    font-size: 38px;
    transform: translateX(2px);
  }
  .hex-icon-text-xs {
    font-size: 34px;
  }
  .hex-icon-text-sm2 {
    font-size: 42px;
  }
  .hex-icon-text-up {
    transform: translateY(-3px);
  }
  .hex-icon-text-lg {
    font-size: 54px;
  }

  .hex-icon-img {
    filter: brightness(0) saturate(0);
    opacity: 0.8;
    transition: opacity 0.2s ease;
  }

  /* ── Hint ───────────────────────────────────────── */
  .hint-text {
    position: absolute;
    bottom: 18%;
    left: 50%;
    transform: translateX(-50%);
    font-size: 10px;
    font-weight: 400;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: #5a6468;
    opacity: 0;
    transition: opacity 0.4s ease;
    pointer-events: none;
  }
  .hint-text.visible {
    opacity: 0.6;
  }

  /* ── Wallet tag (bottom-left corner) ───────────── */
  .wallet-tag {
    position: absolute;
    bottom: 24px;
    left: 16px;
    font-size: 13px;
    font-weight: 500;
    letter-spacing: 0.06em;
    font-family: "Inter", "SF Mono", monospace;
    opacity: 0;
    transition: opacity 0.35s ease;
    filter: drop-shadow(0 0 6px currentColor);
    pointer-events: none;
  }
  .wallet-tag.visible {
    opacity: 0.85;
  }

  /* ── Tooltip on drag target ────────────────────── */
  .hex-tooltip {
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.06em;
    opacity: 0;
    transition: opacity 0.15s ease;
  }
  .hex-scale.hex-target .hex-tooltip {
    opacity: 0.9;
    filter: url(#textGlow);
  }
  @keyframes idlePulse {
    0%, 100% { opacity: 0.7; }
    50% { opacity: 1; }
  }
  .hex-root:has(.hex-center:not(.hex-hidden)) .hex-center .hex-border {
    animation: idlePulse 3s ease-in-out infinite;
  }

  /* ── Center hex press animation ─────────────────── */
  @keyframes hexPress {
    0%   { transform: scale(1); }
    40%  { transform: scale(1.12); }
    100% { transform: scale(1); }
  }
  .hex-press {
    animation: hexPress 0.2s cubic-bezier(0.34, 1.56, 0.64, 1);
  }
</style>
