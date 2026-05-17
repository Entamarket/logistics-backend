import { cookieSecurity } from "../components";

export const feedbackPaths = {
  "/api/feedback/mine": {
    get: {
      tags: ["Feedback"],
      summary: "List feedback submitted by current client",
      security: cookieSecurity,
      responses: {
        "200": {
          description: "Feedback list",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { type: "array", items: { $ref: "#/components/schemas/Feedback" } },
                },
              },
            },
          },
        },
        "403": { description: "Client access required", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/feedback": {
    post: {
      tags: ["Feedback"],
      summary: "Submit feedback for a delivered shipment (client)",
      security: cookieSecurity,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["shipmentId", "rating"],
              properties: {
                shipmentId: { type: "string", example: "664a1b2c3d4e5f6789012345" },
                rating: { type: "integer", minimum: 1, maximum: 5, example: 5 },
                comment: { type: "string", example: "Excellent service!" },
              },
            },
          },
        },
      },
      responses: {
        "201": {
          description: "Feedback created",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string", example: "Feedback submitted" },
                  data: { $ref: "#/components/schemas/Feedback" },
                },
              },
            },
          },
        },
        "400": { description: "Invalid shipment state", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "403": { description: "Not authorized", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
};
