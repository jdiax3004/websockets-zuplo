import { environment, ZuploContext, ZuploRequest } from "@zuplo/runtime";

interface TriggeredRule {
  "ruleId": string
  "version": string
  "tags": string[]
  "message": string
  "category": string
  "riskScore": number
  "details": {
    "maskedInput": string
  },
  "action": "deny" | "warn"
  "selector": string
}

interface AIFirewallResponse {
  "overallRiskScore": number
  "rulesTriggered": TriggeredRule[],
  "userApplicationId": string,
  "clientRequestId": string
}

async function checkFirewallForAi(data: string, context: ZuploContext) {

  const aiFirewallResponse = await fetch(`https://aisec.akamai.com/fai/v1/fai-configurations/${environment.AI_FIREWALL_CONFIG_ID}/detect`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Fai-Api-Key": environment.AI_FIREWALL_KEY
    },
    body: JSON.stringify({
      "clientRequestId": crypto.randomUUID(),
      "llmInput": data
    })
  })

  const responseText = await aiFirewallResponse.text();
  context.log.debug({
    status: aiFirewallResponse.status,
    statusText: aiFirewallResponse.statusText,
    body: responseText
  });

  if (aiFirewallResponse.status !== 200) {
    throw new Error(`AI Firewall request failed. Status: ${aiFirewallResponse.status}, status text: ${aiFirewallResponse.statusText}`);
  }

  const response: AIFirewallResponse = JSON.parse(responseText) as AIFirewallResponse;

  return response;
}

export async function inboundFirewallPolicy(
  data: any,
  target: WebSocket,
  source: WebSocket,
  request: ZuploRequest,
  context: ZuploContext
) {

  try {
    const result = await checkFirewallForAi(data, context);

    const shouldDeny = result.rulesTriggered.filter(rule => rule.action === "deny");

    if (shouldDeny.length === 0) {
      return data;
    }

    source.send(`AI Firewall has denied forwarding this incoming message. ${shouldDeny[0].message} (Rule: ${shouldDeny[0].ruleId})`);
    // you could also send something to the source (origin) here if you like
    // returning undefined here stops the message sequence for this message
    return;
  }
  catch (err) {
    context.log.error(err);
  }

  // in case of error, just go ahead
  return data;
}

export async function outboundFirewallPolicy(
  data: any,
  target: WebSocket,
  source: WebSocket,
  request: ZuploRequest,
  context: ZuploContext
) {

  // to test outbound interception you can 
  // data = "532-90-8976"

  try {
    const result = await checkFirewallForAi(data, context);

    const shouldDeny = result.rulesTriggered.filter(rule => rule.action === "deny");

    if (shouldDeny.length === 0) {
      return data;
    }

    target.send(`AI Firewall has denied forwarding the outgoing message. ${shouldDeny[0].message} (Rule: ${shouldDeny[0].ruleId})`);
    // you could also send something to the source (origin) here if you like
    // returning undefined here stops the message sequence for this message
    return;
  }
  catch (err) {
    context.log.error(err);
  }

  // in case of error, don't block
  return data;
}