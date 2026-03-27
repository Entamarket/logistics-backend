import jwt from "jsonwebtoken";
import type { Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { logger } from "../shared/lib/logger";

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production";

const userIdToSockets = new Map<string, Set<WebSocket>>();

function trackSocket(userId: string, ws: WebSocket): void {
  let set = userIdToSockets.get(userId);
  if (!set) {
    set = new Set();
    userIdToSockets.set(userId, set);
  }
  set.add(ws);
}

function untrackSocket(userId: string, ws: WebSocket): void {
  const set = userIdToSockets.get(userId);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) {
    userIdToSockets.delete(userId);
  }
}

export function broadcastToUser(userId: string, payload: unknown): void {
  const set = userIdToSockets.get(userId);
  if (!set || set.size === 0) return;
  const data = JSON.stringify(payload);
  for (const ws of set) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  }
}

export function initWebSocketServer(httpServer: Server): WebSocketServer {
  const wss = new WebSocketServer({ server: httpServer, path: "/ws" });

  wss.on("connection", (ws: WebSocket, req) => {
    try {
      const host = req.headers.host || "localhost";
      const url = new URL(req.url || "", `http://${host}`);
      const token = url.searchParams.get("token");
      if (!token) {
        ws.close(4001, "Missing token");
        return;
      }
      const decoded = jwt.verify(token, JWT_SECRET) as { id?: string };
      const userId = decoded.id;
      if (!userId) {
        ws.close(4002, "Invalid token");
        return;
      }
      trackSocket(userId, ws);
      ws.send(JSON.stringify({ event: "connected" }));
      ws.on("close", () => untrackSocket(userId, ws));
      ws.on("error", () => untrackSocket(userId, ws));
    } catch (e) {
      logger.warn("WebSocket connection rejected", {
        message: e instanceof Error ? e.message : String(e),
      });
      ws.close(4003, "Unauthorized");
    }
  });

  logger.info("WebSocket server listening on /ws");
  return wss;
}
