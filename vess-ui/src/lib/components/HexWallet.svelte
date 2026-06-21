<script lang="ts">
  import { onMount } from "svelte";
  import { getBalance, getBills, type BalanceData } from "../rpc/client";

  // ── Types ──────────────────────────────────────────────
  type Asset = "vess" | "bitcoin" | "vichor";
  type Mode = "idle" | "pressed" | "dragging";
  type ActionId = "send" | "add" | "swap" | "settings";

  interface AssetInfo {
    label: string;
    color: string;
    glow: string;
    icon: string;
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

  onMount(async () => {
    try { balance = await getBalance(); } catch { /* node offline */ }
  });

  // ── State ─────────────────────────────────────────────
  let selected: Asset = "vess";
  let mode: Mode = "idle";
  let dragTarget: number | null = null;

  const ASSETS: Record<Asset, AssetInfo> = {
    vess:   { label: "Vess",    color: "#5fb5d2", glow: "rgba(95,181,210,0.35)",   icon: "◆" },
    bitcoin:{ label: "Bitcoin", color: "#f28e13", glow: "rgba(242,142,19,0.35)",   icon: "₿" },
    vichor: { label: "Vichor",  color: "#ccff00", glow: "rgba(204,255,0,0.35)",    icon: "⬡" },
  };

  const ACTION_COLORS: Record<ActionId, string> = {
    send:     "#3b82f6",
    add:      "#10b981",
    swap:     "#ef4444",
    settings: "#6b7280",
  };

  // ── Hexagon geometry (pointy-top) ─────────────────────
  const R = 30;                         // hex radius in SVG units
  const SQRT3 = Math.sqrt(3);
  const CENTER = { x: 0, y: 80 };       // ~30% from viewBox bottom

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
      x: CENTER.x + SQRT3 * (q + r / 2) * R,
      y: CENTER.y + 1.5 * r * R,
    };
  }

  const NEIGHBOR_PX = NEIGHBOR_AXIAL.map(({ q, r }) => axialToPixel(q, r));
  const ALL_POSITIONS = [CENTER, ...NEIGHBOR_PX];

  // SVG hexagon path (pointy-top, first vertex at top)
  function hexPath(r: number): string {
    const pts: string[] = [];
    for (let i = 0; i < 6; i++) {
      const a = (Math.PI / 180) * (60 * i - 90);
      pts.push(`${(r * Math.cos(a)).toFixed(3)},${(r * Math.sin(a)).toFixed(3)}`);
    }
    return pts.join(" ");
  }

  const DARK_ICON = "#1c2224";           // panel navy for icons on asset hexes & action drag targets

  const H = hexPath(R);                 // outer hex path
  const HI = hexPath(R * 0.82);         // inner (icon area) hex path

  // ── Derived: outer assets ─────────────────────────────
  $: otherAssets = (["vess", "bitcoin", "vichor"] as Asset[]).filter(a => a !== selected);

  // ── Build hex item for each grid position ─────────────
  $: items = ALL_POSITIONS.map((pos, i): HexItem => {
    if (i === 0) {
      // Center — current selected asset
      const a = ASSETS[selected];
      return { id: selected, label: a.label, color: a.color, glow: a.glow, icon: a.icon, isAsset: true, isCenter: true };
    }
    switch (i) {
      case 1: return { id: "send",  label: "Send",  color: ACTION_COLORS.send,  glow: "rgba(59,130,246,0.3)",  icon: "➤", isAsset: false, isCenter: false };
      case 2: return { id: "add",   label: "Add",   color: ACTION_COLORS.add,   glow: "rgba(16,185,129,0.3)",  icon: "+", isAsset: false, isCenter: false };
      case 3: return { id: "swap",  label: "Swap",  color: ACTION_COLORS.swap,  glow: "rgba(239,68,68,0.3)",   icon: "⇄", isAsset: false, isCenter: false };
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
  $: currentAsset = ASSETS[selected];
  $: displayAmount = (() => {
    if (!balance) return "---";
    switch (selected) {
      case "vess":    return String(balance.balance ?? 0);
      case "bitcoin": return (balance.watch_only_balance ?? 0).toFixed(8);
      case "vichor":  return String(balance.vichor_balance ?? 0);
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
      // Swap: set selected to that asset
      selected = item.id as Asset;
    } else if (!item.isAsset) {
      // Action
      switch (item.id) {
        case "send":     onNavigate("send"); break;
        case "add":      onNavigate("mint"); break;
        case "swap":     onNavigate("swap"); break;
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
    <span class="amount-label">{currentAsset.label}</span>
    <span class="amount-value">{displayAmount}</span>
  </div>

  <!-- SVG hexagonal grid -->
  <svg
    bind:this={svgEl}
    class="hex-svg"
    viewBox="-120 -170 240 380"
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
      <circle cx="0" cy={CENTER.y} r={R * 1.8} fill="none" stroke="currentColor" stroke-width="0.3" stroke-dasharray="3 6" />
    </g>

    {#each items as item, i}
      {@const pos = ALL_POSITIONS[i]}
      {@const isCenter = i === 0}
      {@const isTarget = mode === "dragging" && dragTarget === i}
      {@const isOuter = !isCenter}
      {@const visible = isCenter || mode !== "idle"}
      {@const assetFill = item.isAsset ? item.color : "transparent"}
      {@const assetFillOpacity = item.isAsset ? 0.9 : 0}
      {@const iconColor = item.isAsset ? DARK_ICON : (isTarget ? DARK_ICON : item.color)}

      <g
        transform="translate({pos.x.toFixed(2)},{pos.y.toFixed(2)})"
        class="hex-group"
        class:hex-hidden={!visible}
        class:hex-target={isTarget}
        class:hex-center={isCenter}
        style="color: {item.color}"
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
          opacity={item.isAsset ? 1 : (isCenter ? 0.8 : 0.5)}
          class="hex-border"
        />

        <!-- Action hex: subtle fill normally, solid fill on drag target -->
        {#if !item.isAsset}
          <path
            d={H}
            fill="currentColor"
            opacity={isTarget ? 0.88 : (isCenter ? 0.08 : 0.05)}
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

        <!-- Glow ring (outer hexes on hover) -->
        {#if isOuter}
          <path
            d={H}
            fill="none"
            stroke="currentColor"
            stroke-width="2.5"
            opacity={isTarget ? 0.7 : 0}
            filter="url(#hexGlow)"
            class="hex-glow-ring"
          />
        {/if}

        <!-- Center hex has subtle radial fill -->
        {#if isCenter}
          <path d={H} fill="url(#centerGrad)" />
          <!-- Inner hex outline -->
          <path
            d={HI}
            fill="none"
            stroke={item.isAsset ? DARK_ICON : "currentColor"}
            stroke-width="0.7"
            opacity="0.3"
          />
        {/if}

        <!-- Icon -->
        <text
          x="0"
          y={isCenter ? "2" : "1"}
          text-anchor="middle"
          dominant-baseline="central"
          class="hex-icon"
          class:hex-icon-lg={isCenter}
          fill={iconColor}
          opacity={isCenter ? 1 : 0.85}
        >{item.icon}</text>

        <!-- Label (outer hexes only, appears on press) -->
        {#if isOuter}
          <text
            x="0"
            y={R + 17}
            text-anchor="middle"
            class="hex-label"
            fill="currentColor"
            opacity={mode !== "idle" ? 0.65 : 0}
          >{item.label}</text>
        {/if}
      </g>
    {/each}
  </svg>

  <!-- Hint text at bottom (idle only) -->
  <div class="hint-text" class:visible={mode === "idle"}>
    hold to navigate
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
  .amount-label {
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.12em;
    text-transform: uppercase;
  }
  .amount-value {
    font-size: 34px;
    font-weight: 200;
    letter-spacing: 0.03em;
    font-variant-numeric: tabular-nums;
    font-family: "Inter", "SF Mono", "Fira Code", monospace;
  }

  /* ── Hex groups ─────────────────────────────────── */
  .hex-group {
    transition: opacity 0.3s ease, transform 0.25s ease;
    cursor: pointer;
  }
  .hex-hidden {
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.2s ease, transform 0.2s ease;
  }
  .hex-center {
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

  .hex-icon {
    font-size: 18px;
    transition: opacity 0.2s ease, fill 0.25s ease;
  }
  .hex-icon-lg {
    font-size: 28px;
  }

  .hex-label {
    font-size: 10px;
    font-weight: 500;
    letter-spacing: 0.08em;
    transition: opacity 0.25s ease;
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

  /* ── Center hex idle pulse ──────────────────────── */
  @keyframes idlePulse {
    0%, 100% { opacity: 0.7; }
    50% { opacity: 1; }
  }
  .hex-root:has(.hex-center:not(.hex-hidden)) .hex-center .hex-border {
    animation: idlePulse 3s ease-in-out infinite;
  }
</style>
