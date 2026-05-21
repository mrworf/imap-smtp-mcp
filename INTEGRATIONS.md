# Integration Guide

This guide covers client-specific setup for Personal Email Connector. The server itself exposes a remote MCP endpoint at `/sse`, OAuth metadata under `/.well-known/`, and an OAuth authorization-code + PKCE flow with Dynamic Client Registration.

Use the deployment guide for hosting, TLS, storage, and reverse-proxy details. Use this guide for LLM client behavior and connector setup notes.

## ChatGPT

ChatGPT is the primary tested integration target for this project.

Use the public MCP URL in ChatGPT Apps & Connectors:

```text
https://mail-mcp.example.com/sse
```

ChatGPT discovers OAuth from:

```text
https://mail-mcp.example.com/.well-known/oauth-protected-resource
https://mail-mcp.example.com/.well-known/oauth-authorization-server
```

The server supports Dynamic Client Registration and authorization-code + PKCE. Users authorize by entering separate IMAP and SMTP credentials. The IMAP login is verified before tokens are issued.

Restrict Dynamic Client Registration to known redirect destinations. For ChatGPT, allow connector OAuth redirects with:

```env
OAUTH_ALLOWED_REDIRECT_URI_PATTERNS=^https://chatgpt\.com/connector/oauth/[A-Za-z0-9_-]+$
```

After changing connector metadata such as `MCP_APP_DISPLAY_NAME`, descriptions, website, privacy policy, or terms URLs, refresh or reconnect the app in ChatGPT Developer Mode before relying on ChatGPT's app picker or tool-routing behavior. ChatGPT may cache app metadata between connector updates.

ChatGPT tends to default to Gmail for generic email prompts regardless if you have Gmail available or not. In an empty chat, set a ChatGPT memory or preference with `remember that I don't use gmail and instead use the Personal Email Connector` so future email prompts are more likely to route here. This is not a server-side guarantee. For sensitive or ambiguous requests, still include `use Personal Email Connector, not Gmail` in the prompt, or the `@Personal Email Connector` reference.

OpenAI references:

- [Building MCP servers for ChatGPT and API integrations](https://platform.openai.com/docs/mcp/)
- [ChatGPT Developer mode](https://platform.openai.com/docs/guides/developer-mode)

## Claude

Claude remote MCP use is untested for this project.

Anthropic documents remote MCP support for Claude API and Claude Code flows. Those clients can use HTTP/SSE or Streamable HTTP transports and OAuth bearer tokens, but this project has not validated the full OAuth setup with Claude. Native stdio for Claude Desktop is not implemented by this server; use an HTTP-capable Claude client or an external bridge if your workflow requires stdio.

Expected starting point:

- Server URL: `https://mail-mcp.example.com/sse`
- Authentication: complete OAuth with an MCP inspector or a Claude client that supports remote OAuth, then provide the resulting bearer token if the client requires manual token configuration.

Anthropic references:

- [MCP connector](https://docs.anthropic.com/en/docs/agents-and-tools/mcp-connector)
- [Connect Claude Code to tools via MCP](https://docs.anthropic.com/en/docs/claude-code/mcp)

## Mistral Le Chat

Mistral Le Chat is likely compatible but untested for this project.

Mistral documents custom MCP connectors over HTTPS, support for OAuth 2.1 with Dynamic Client Registration, and Streamable HTTP as the current standard. That overlaps with this server's intended remote MCP shape, but compatibility has not been verified against Le Chat.

Expected starting point:

- Server URL: `https://mail-mcp.example.com/sse`
- Authentication: OAuth 2.1 with Dynamic Client Registration.
- Transport: Streamable HTTP-compatible JSON-RPC at `/sse`.

Known caution: Mistral documents current limitations for custom MCP connectors, including incomplete support for all MCP capabilities. Validate read, send, and write tools with a dedicated test mailbox before using a real mailbox.

Mistral reference:

- [MCP Connectors](https://docs.mistral.ai/le-chat/knowledge-integrations/connectors/mcp-connectors)

## Perplexity

Perplexity custom remote MCP compatibility is unknown and unsupported by this project at this time.

Before attempting integration, confirm that the Perplexity client you are using supports custom remote MCP servers, HTTPS transport, OAuth/DCR or bearer-token authentication, and MCP tool calls. If those details are not available, treat this server as unsupported for Perplexity.

## Other MCP Clients

Other clients should start from these requirements:

- Public HTTPS reachability with a valid certificate.
- Remote MCP over Streamable HTTP-compatible JSON-RPC at `/sse`.
- OAuth authorization-code + PKCE support, preferably with Dynamic Client Registration, or a documented way to supply a bearer token acquired out of band.
- Tool discovery and tool-call support for the advertised MCP tools.
- Explicit operator review before enabling write-capable tools against a real mailbox.

Use a dedicated test mailbox first. Manual mailbox verification depends on external IMAP/SMTP reachability, client-specific OAuth behavior, and the client's support for remote MCP transports.
