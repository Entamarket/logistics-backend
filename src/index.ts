import http from "http";
import express from "express";
import dotenv from "dotenv";
import { connectDatabase } from "./config/database";
import { setupRoutes } from "./routes/api";
import { setupMiddleware } from "./shared/middlewares/middleware";
import { logger } from "./shared/lib/logger";
import { ShipmentService } from "./modules/shipment/shipment.service";
import { initWebSocketServer } from "./realtime/wsHub";

dotenv.config();

const app = express();

// Setup middleware
setupMiddleware(app);

// Setup routes
setupRoutes(app);

const PORT = process.env.PORT || 4000;

const shipmentService = new ShipmentService();

const startServer = async () => {
  try {
    await connectDatabase();
    setInterval(() => {
      shipmentService.processExpiredRiderOffers().catch((err) => {
        logger.error("Rider offer expiry job failed", {
          message: err instanceof Error ? err.message : String(err),
        });
      });
    }, 20_000);

    const server = http.createServer(app);
    initWebSocketServer(server);

    server.listen(PORT, () => {
      logger.info(`Server started on port ${PORT}`);
    });
  } catch (error) {
    logger.error("Failed to start server", { error });
    process.exit(1);
  }
};

startServer();
