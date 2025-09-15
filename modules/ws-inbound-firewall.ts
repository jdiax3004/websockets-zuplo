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

export async function inboundFirewallPolicy(
  data: any,
  target: WebSocket,
  source: WebSocket,
  request: ZuploRequest,
  context: ZuploContext
) {

  const aiFirewallResponse = await fetch('https://aisec.akamai.com/fai/v1/fai-configurations/1129/detect',{
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

  if (aiFirewallResponse.status !== 200) {
    context.log.warn(`AI Firewall request failed. Status: ${aiFirewallResponse.status}, status text: ${aiFirewallResponse.statusText}`)
    return data;
  }

  const firewallDetails = await aiFirewallResponse.clone().json() as AIFirewallResponse
  const shouldDeny = firewallDetails.rulesTriggered.filter(rule => rule.action === "deny")

  // If AI Firewall response is denied then we don't forward data to websocket server
  if (shouldDeny.length > 0) {
    context.log.warn("AI Firewall has denied the request")
    context.log.error(shouldDeny)
    source.send(`AI Firewall has denied forwarding this message. ${shouldDeny[0].message} (Rule: ${shouldDeny[0].ruleId})`)
    return
  }
 

  return data;
}