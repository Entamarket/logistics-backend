import { Request, Response } from "express";
import { ShipmentService } from "../shipment/shipment.service";
import { verifyWebhookSignature } from "../../shared/lib/paystack.service";
import { logger } from "../../shared/lib/logger";

const shipmentService = new ShipmentService();

export async function paystackWebhook(req: Request, res: Response): Promise<void> {
  try {
    const signature = req.headers["x-paystack-signature"] as string | undefined;
    const rawBody = req.body as Buffer;
    if (!Buffer.isBuffer(rawBody) || !verifyWebhookSignature(rawBody, signature)) {
      res.status(401).json({ success: false, message: "Invalid signature" });
      return;
    }

    const event = JSON.parse(rawBody.toString("utf8")) as Parameters<
      ShipmentService["handlePaystackWebhook"]
    >[0];
    await shipmentService.handlePaystackWebhook(event);
    res.status(200).json({ success: true });
  } catch (error: unknown) {
    logger.error("Paystack webhook error", {
      message: error instanceof Error ? error.message : String(error),
    });
    res.status(500).json({ success: false, message: "Webhook processing failed" });
  }
}
