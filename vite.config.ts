import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv, type Plugin } from "vite";

function trimTrailingSlash(value: string) {
  return value.replace(/\/+$/, "");
}

function createOAuthMetadata(baseUrl: string) {
  const normalizedBaseUrl = trimTrailingSlash(baseUrl || "https://example.com");
  return {
    client_id: `${normalizedBaseUrl}/oauth/client-metadata.json`,
    client_name: "PLC Passkey",
    client_uri: `${normalizedBaseUrl}/`,
    logo_uri: `${normalizedBaseUrl}/favicon.svg`,
    redirect_uris: [`${normalizedBaseUrl}/`],
    scope: "atproto identity:*",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    application_type: "web",
    dpop_bound_access_tokens: true,
  };
}

function createOAuthMetadataPlugin(publicUrl: string): Plugin {
  return {
    name: "oauth-client-metadata",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url !== "/oauth/client-metadata.json") {
          next();
          return;
        }

        const forwardedProto = req.headers["x-forwarded-proto"];
        const protocol =
          typeof forwardedProto === "string"
            ? forwardedProto.split(",")[0]!.trim()
            : server.config.server.https
              ? "https"
              : "http";
        const host = req.headers.host ?? "localhost:5173";
        const baseUrl = publicUrl || `${protocol}://${host}`;

        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(JSON.stringify(createOAuthMetadata(baseUrl), null, 2));
      });
    },
    generateBundle() {
      this.emitFile({
        type: "asset",
        fileName: "oauth/client-metadata.json",
        source: JSON.stringify(createOAuthMetadata(publicUrl), null, 2),
      });
    },
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");

  return {
    plugins: [react(), createOAuthMetadataPlugin(env.VITE_PUBLIC_URL)],
    server: {
      allowedHosts: ["50da-161-45-254-242.ngrok-free.app"],
    },
  };
});
