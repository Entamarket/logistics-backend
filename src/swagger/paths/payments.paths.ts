export const paymentPaths = {
  "/api/webhooks/paystack": {
    post: {
      tags: ["Payments"],
      summary: "Paystack webhook (charge.success)",
      description:
        "Called by Paystack with `x-paystack-signature` HMAC. No authentication cookie. Raw JSON body required for signature verification.",
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: { type: "object", description: "Paystack event payload" },
          },
        },
      },
      responses: {
        "200": { description: "Event accepted" },
        "401": { description: "Invalid signature" },
      },
    },
  },
};
