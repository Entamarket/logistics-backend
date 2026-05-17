import { swaggerComponents } from "./components";
import { openApiPaths } from "./paths";

const port = process.env.PORT || "4000";
const serverUrl = process.env.SWAGGER_SERVER_URL || `http://localhost:${port}`;

export const openApiSpec = {
  openapi: "3.0.3",
  info: {
    title: "Entamarket Logistics API",
    version: "1.0.0",
    description: [
      "REST API for the Entamarket logistics platform.",
      "",
      "**Authentication:** Most routes use an httpOnly `token` cookie set by `POST /api/auth/login`.",
      "In Swagger UI, log in via `/api/auth/login` first (browser), or add `Cookie: token=<jwt>` manually.",
      "",
      "**WebSocket:** `ws://<host>/ws?token=<jwt>` — obtain JWT from `GET /api/auth/ws-token`.",
    ].join("\n"),
  },
  servers: [{ url: serverUrl, description: "API server" }],
  tags: [
    { name: "Health", description: "Server status" },
    { name: "Auth", description: "Signup, login, password reset" },
    { name: "Shipments", description: "Create and manage deliveries" },
    { name: "Riders", description: "Rider profile and admin rider management" },
    { name: "Notifications", description: "In-app notifications" },
    { name: "Feedback", description: "Post-delivery ratings" },
    { name: "Complaints", description: "Client and rider complaints" },
    { name: "Admin", description: "Admin dashboard APIs" },
  ],
  paths: openApiPaths,
  components: swaggerComponents,
};
