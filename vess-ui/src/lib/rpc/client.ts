/// RPC client for the Vess artery node.
/// Communicates via Tauri HTTP plugin or direct fetch to the node's RPC port.

const DEFAULT_RPC_URL = "http://127.0.0.1:9821";

let _rpcUrl: string | null = null;

async function getRpcUrl(): Promise<string> {
  if (_rpcUrl) return _rpcUrl;

  // In Tauri: trust the backend port directly (no HTTP validation needed).
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    const port: number = await invoke("get_rpc_port");
    const url = `http://127.0.0.1:${port}`;
    _rpcUrl = url;
    return url;
  } catch { /* not in Tauri */ }

  // Fallback for browser dev mode: scan ports 9821–9851.
  for (let port = 9821; port <= 9851; port++) {
    try {
      const url = `http://127.0.0.1:${port}`;
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 2000);
      const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"method":"node_info"}', signal: ctrl.signal });
      clearTimeout(t);
      if (res.ok) { _rpcUrl = url; return url; }
    } catch { /* try next */ }
  }

  return DEFAULT_RPC_URL;
}

export interface RpcRequest {
  method: string;
  params: Record<string, unknown>;
}

export interface RpcResponse {
  ok: boolean;
  data?: unknown;
  error?: string;
}

export interface BalanceData {
  balance: number;
  bill_count: number;
  watch_only_balance?: number;
  vichor_balance?: number;
}

export interface NodeInfo {
  node_id: string;
  peer_count: number;
  estimated_network_size: number;
  tag_count: number;
  ownership_count: number;
  version_hash: string;
}

export interface TagInfo {
  tag: string;
  address: string;
}

export interface BillInfo {
  mint_id: string;
  denomination: number;
  chain_tip: string;
  chain_depth: number;
  asset: string;
}

export interface SwapOffer {
  offer_id: string;
  offer_asset: string;
  offer_amount: number;
  want_asset: string;
  want_amount: number;
  seller_tag: string;
  hash_lock: string;
  expires_at: number;
}

export async function rpcCall(method: string, params: Record<string, unknown> = {}): Promise<RpcResponse> {
  // Use Tauri proxy (raw TCP with proper auth token).
  const { invoke } = await import("@tauri-apps/api/core");
  return await invoke<RpcResponse>("rpc_proxy", { method, params: params || {} });
}

export async function getBalance(): Promise<BalanceData> {
  const res = await rpcCall("balance");
  return res as unknown as BalanceData;
}

export async function getNodeInfo(): Promise<NodeInfo> {
  const res = await rpcCall("node_info");
  return res as unknown as NodeInfo;
}

export async function sendPayment(recipientTag: string, amount: number, memo?: string): Promise<string> {
  const res = await rpcCall("send", { recipient_tag: recipientTag, amount, memo });
  if (res.error) throw new Error(res.error);
  return (res as any).payment_id || "";
}

export async function sendBitcoin(address: string, amountBtc: number, memo?: string): Promise<string> {
  const res = await rpcCall("send_bitcoin", { address, amount_btc: amountBtc, memo });
  if (res.error) throw new Error(res.error);
  return (res as any).txid || "";
}

export async function lookupTag(tag: string): Promise<TagInfo> {
  const res = await rpcCall("tag_lookup", { tag });
  return res as unknown as TagInfo;
}

export async function getVessTag(): Promise<string> {
  const res = await rpcCall("get_tag");
  if (res.error) throw new Error(res.error);
  return (res as any)?.tag || "";
}

export interface CheckMyTagResult {
  tag: string | null;
  valid: boolean;
  hardened: boolean;
  message: string;
}

export async function checkMyTag(): Promise<CheckMyTagResult> {
  const res = await rpcCall("check_my_tag");
  return (res as any) || { tag: null, valid: false, hardened: false, message: "error" };
}

export async function storeVessTag(tag: string): Promise<void> {
  const res = await rpcCall("tag_register", { tag });
  if (res.error) throw new Error(res.error);
}

export async function registerTag(tag: string): Promise<void> {
  const res = await rpcCall("tag_register", { tag });
  if (res.error) throw new Error(res.error);
}

export interface WalletInfo {
  tag: string;
  path: string;
  has_password: boolean;
  created_at: number | null;
}

export async function listWallets(): Promise<WalletInfo[]> {
  const res = await rpcCall("list_wallets");
  return ((res as any)?.wallets as WalletInfo[]) || [];
}

export async function unlockWallet(walletPath: string, password: string): Promise<void> {
  const res = await rpcCall("wallet_unlock", { wallet_path: walletPath, password });
  if (res.error) throw new Error(res.error);
}

export async function setWalletPassword(currentPassword: string, newPassword: string): Promise<void> {
  const res = await rpcCall("wallet_set_password", { current_password: currentPassword, new_password: newPassword });
  if (res.error) throw new Error(res.error);
}

export async function getBills(): Promise<BillInfo[]> {
  const res = await rpcCall("bills");
  return ((res as any)?.bills as BillInfo[]) || [];
}

export async function mintTimelock(
  amountSats: number,
  durationYears: number,
  vichorBurned?: number
): Promise<string> {
  const res = await rpcCall("mint_timelock", {
    amount_sats: amountSats,
    duration_years: durationYears,
    vichor_burned: vichorBurned || 0,
  });
  if (res.error) throw new Error(res.error);
  return (res as any)?.txid || "";
}

export async function listSwapOffers(assetA: string = "vess", assetB: string = "vichor"): Promise<SwapOffer[]> {
  const res = await rpcCall("swap_list", { asset_a: assetA, asset_b: assetB });
  return (res as any)?.offers || [];
}

export async function createSwapOffer(
  offerAsset: string,
  offerAmount: number,
  wantAsset: string,
  wantAmount: number,
  recipient: string,
  expiresInSecs: number = 86400
): Promise<string> {
  const res = await rpcCall("swap_propose", {
    offer_asset: offerAsset,
    offer_amount: offerAmount,
    want_asset: wantAsset,
    want_amount: wantAmount,
    recipient,
    expires_in_secs: expiresInSecs,
  });
  if (res.error) throw new Error(res.error);
  return (res as any)?.hash_lock || "";
}

export async function exportSeedPhrase(): Promise<string[]> {
  const res = await rpcCall("export_seed");
  if (res.error) throw new Error(res.error);
  const words = (res as any)?.phrase?.split(" ") || [];
  if (words.length === 0) throw new Error("Seed phrase not available");
  return words;
}

// ── Wallet onboarding ──────────────────────────────────

export interface WalletStatus {
  exists: boolean;
  tag?: string;
  node_id?: string;
}

export async function walletStatus(): Promise<WalletStatus> {
  const res = await rpcCall("wallet_status");
  return (res as unknown as WalletStatus) || { exists: false };
}

export async function checkTag(tag: string): Promise<{ available: boolean; reason?: string }> {
  const res = await rpcCall("check_tag", { tag });
  return (res as any) || { available: false, reason: "network error" };
}

export async function createWallet(tag: string): Promise<{ phrase: string[] }> {
  const res = await rpcCall("create_wallet", { tag });
  if (res.error) throw new Error(res.error);
  const phrase = (res as any)?.phrase;
  if (!phrase || typeof phrase !== "string") throw new Error("Invalid response");
  return { phrase: phrase.split(" ") };
}

export async function recoverWallet(phrase: string[], tag: string): Promise<void> {
  const res = await rpcCall("recover_wallet", { phrase: phrase.join(" "), tag });
  if (res.error) throw new Error(res.error);
}

export async function getCenturyLocks(): Promise<CenturyLockInfo[]> {
  const res = await rpcCall("century_locks");
  return (res as any)?.locks || [];
}

export interface CenturyLockInfo {
  lock_id: string;
  total_sats: number;
  per_block_vess: number;
  start_block: number;
  end_block: number;
  last_claimed_block: number;
  unclaimed_blocks: number;
  remaining_vess: number;
  active: boolean;
  created_at: number;
}
