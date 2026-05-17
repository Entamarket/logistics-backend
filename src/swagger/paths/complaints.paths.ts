import { cookieSecurity } from "../components";

export const complaintPaths = {
  "/api/complaints": {
    post: {
      tags: ["Complaints"],
      summary: "Submit a complaint (client or rider)",
      security: cookieSecurity,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["subject", "message", "phone"],
              properties: {
                subject: { type: "string", maxLength: 200, example: "Late delivery" },
                message: { type: "string", minLength: 10, maxLength: 5000, example: "The rider arrived two hours late without notice." },
                phone: { type: "string", example: "+2348012345678" },
                relatedShipmentId: {
                  type: "string",
                  description: "Optional shipment MongoDB id",
                  example: "664a1b2c3d4e5f6789012345",
                },
              },
            },
          },
        },
      },
      responses: {
        "201": {
          description: "Complaint submitted",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string", example: "Complaint submitted" },
                  data: { $ref: "#/components/schemas/Complaint" },
                },
              },
            },
          },
        },
        "400": { description: "Validation error", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "403": { description: "Only clients and riders may submit", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/complaints/mine": {
    get: {
      tags: ["Complaints"],
      summary: "List complaints submitted by current user",
      security: cookieSecurity,
      responses: {
        "200": {
          description: "Complaint list",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { type: "array", items: { $ref: "#/components/schemas/Complaint" } },
                },
              },
            },
          },
        },
        "401": { description: "Not authenticated", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
};
