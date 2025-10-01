import { environment, ZuploContext, ZuploRequest } from "@zuplo/runtime";

interface TriggeredRule {
  ruleId: string;
  version: string;
  tags: string[];
  message: string;
  category: string;
  riskScore: number;
  details: { maskedInput: string };
  action: "deny" | "alert";
  selector: string;
}

interface AIFirewallResponse {
  overallRiskScore: number;
  rulesTriggered: TriggeredRule[];
  userApplicationId: string;
  clientRequestId: string;
}

type DetectMode = "input" | "output";

async function detectWithAiFirewall(
  data: string,
  context: ZuploContext,
  mode: DetectMode
): Promise<AIFirewallResponse> {
  const payload =
    mode === "input"
      ? { clientRequestId: crypto.randomUUID(), llmInput: data }
      : { clientRequestId: crypto.randomUUID(), llmOutput: data };

  const url = `https://aisec.akamai.com/fai/v1/fai-configurations/${environment.AI_FIREWALL_CONFIG_ID}/detect`;

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Fai-Api-Key": environment.AI_FIREWALL_KEY,
    },
    body: JSON.stringify(payload),
  });

  const text = await res.text();

  // Debug
  context.log.debug({
    detectMode: mode,
    url,
    status: res.status,
    statusText: res.statusText,
    responseBody: text,
  });

  if (!res.ok) {
    throw new Error(
      `FAI detect failed (${mode}). HTTP ${res.status} ${res.statusText} — ${text?.slice(0, 500)}`
    );
  }

  return JSON.parse(text) as AIFirewallResponse;
}

function mustBeString(data: any): string {
  if (typeof data === "string") return data;
  if (data instanceof Uint8Array) return new TextDecoder().decode(data);
  return String(data);
}

export async function inboundFirewallPolicy(
  data: any,
  target: WebSocket,
  source: WebSocket,
  request: ZuploRequest,
  context: ZuploContext
) {
  try {
    const s = mustBeString(data);
    const result = await detectWithAiFirewall(s, context, "input");

    const denies = result.rulesTriggered.filter(r => r.action === "deny");
    if (denies.length === 0) return data;

    source.send(
      `Firewall for AI denied inbound message: ${denies[0].message} (Rule: ${denies[0].ruleId})`
    );
    return;
  } catch (err) {
    context.log.error({ err, phase: "inbound" });
  }
  return data;
}

export async function outboundFirewallPolicy(
  data: any,
  target: WebSocket,
  source: WebSocket,
  request: ZuploRequest,
  context: ZuploContext
) {
  try {
    const s = mustBeString(data);
    const result = await detectWithAiFirewall(s, context, "output");

    const denies = result.rulesTriggered.filter(r => r.action === "deny");
    if (denies.length === 0) return data;

    target.send(
      `Firewall for AI denied outbound message: ${denies[0].message} (Rule: ${denies[0].ruleId})`
    );
    return;
  } catch (err) {
    context.log.error({ err, phase: "outbound" });
  }
  return data; 
}
