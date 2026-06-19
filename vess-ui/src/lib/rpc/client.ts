/// RPC client for the Vess artery node.
/// Communicates via Tauri HTTP plugin or direct fetch to the node's RPC port.

const DEFAULT_RPC_URL = "http://127.0.0.1:9821";

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

export async function rpcCall(method: string, params: Record<string, unknown> = {}): Promise<RpcResponse> {
  const url = localStorage.getItem("vess_rpc_url") || DEFAULT_RPC_URL;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ method, params }),
  });
  return res.json();
}

export async function getBalance(): Promise<BalanceData> {
  const res = await rpcCall("balance");
  return res.data as BalanceData;
}

export async function getNodeInfo(): Promise<NodeInfo> {
  const res = await rpcCall("node_info");
  return res.data as NodeInfo;
}

export async function sendPayment(recipientTag: string, amount: number, memo?: string): Promise<string> {
  const res = await rpcCall("send", { recipient_tag: recipientTag, amount, memo });
  if (res.error) throw new Error(res.error);
  return res.data as string;
}

export async function lookupTag(tag: string): Promise<TagInfo> {
  const res = await rpcCall("tag_lookup", { tag });
  return res.data as TagInfo;
}

export async function registerTag(tag: string): Promise<void> {
  const res = await rpcCall("tag_register", { tag });
  if (res.error) throw new Error(res.error);
}

export async function getBills(): Promise<BillInfo[]> {
  const res = await rpcCall("bills");
  return (res.data as BillInfo[]) || [];
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
  return res.data as string;
}
