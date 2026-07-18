import { cookieSecurity } from "../components";

const riderResponse = {
  "200": {
    description: "Rider resource",
    content: {
      "application/json": {
        schema: {
          type: "object",
          properties: {
            success: { type: "boolean", example: true },
            data: { $ref: "#/components/schemas/Rider" },
          },
        },
      },
    },
  },
};

export const riderPaths = {
  "/api/riders/me": {
    get: {
      tags: ["Riders"],
      summary: "Get current rider profile",
      security: cookieSecurity,
      responses: {
        ...riderResponse,
        "403": { description: "Rider access required", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "404": { description: "Rider not found", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/riders/me/earnings": {
    get: {
      tags: ["Riders"],
      summary: "Get current rider daily and all-time earnings",
      description:
        "Returns earnings for the authenticated rider. Each delivered shipment whose current riderID is this rider earns a fixed ₦500. Daily buckets use Africa/Lagos calendar days based on the delivered timeline timestamp (fallback: updatedAt). Reassigned deliveries are credited to the final rider only.",
      security: cookieSecurity,
      parameters: [
        {
          name: "days",
          in: "query",
          required: false,
          schema: { type: "integer", minimum: 1, maximum: 31, default: 7 },
          description: "Number of calendar days to include in the daily series (default 7)",
        },
      ],
      responses: {
        "200": {
          description: "Earnings summary",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { $ref: "#/components/schemas/RiderEarningsSummary" },
                },
              },
            },
          },
        },
        "403": {
          description: "Rider access required",
          content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } },
        },
        "404": {
          description: "Rider profile not found",
          content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } },
        },
      },
    },
  },
  "/api/riders/me/location": {
    patch: {
      tags: ["Riders"],
      summary: "Update rider GPS location",
      security: cookieSecurity,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["longitude", "latitude"],
              properties: {
                longitude: { type: "number", example: 3.3792 },
                latitude: { type: "number", example: 6.5244 },
              },
            },
          },
        },
      },
      responses: riderResponse,
    },
  },
  "/api/riders/me/availability": {
    patch: {
      tags: ["Riders"],
      summary: "Update current rider availability for new assignments",
      description:
        "On/off duty toggle only. When true, the rider can receive new shipment offers (including while other jobs are in progress). When false, no new offers are sent; current deliveries continue. Setting true requires active status and verified profile.",
      security: cookieSecurity,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["isAvailable"],
              properties: {
                isAvailable: {
                  type: "boolean",
                  example: true,
                  description:
                    "When true, rider is on duty and eligible for new offers (multiple concurrent jobs allowed). When false, off duty.",
                },
              },
            },
          },
        },
      },
      responses: {
        ...riderResponse,
        "400": {
          description: "Invalid body or cannot go available (inactive/unverified account)",
          content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } },
        },
        "403": { description: "Rider access required", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "404": { description: "Rider profile not found", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/riders": {
    post: {
      tags: ["Riders"],
      summary: "Create rider (admin)",
      security: cookieSecurity,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["firstName", "lastName", "email", "phone", "password"],
              properties: {
                firstName: { type: "string", example: "Chidi" },
                lastName: { type: "string", example: "Eze" },
                email: { type: "string", example: "chidi.rider@example.com" },
                phone: { type: "string", example: "+2348098765432" },
                password: { type: "string", minLength: 8, example: "RiderPass123" },
              },
            },
          },
        },
      },
      responses: {
        "201": riderResponse["200"],
        "403": { description: "Admin access required", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
    get: {
      tags: ["Riders"],
      summary: "List all riders (admin)",
      security: cookieSecurity,
      responses: {
        "200": {
          description: "Rider list",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { type: "array", items: { $ref: "#/components/schemas/Rider" } },
                },
              },
            },
          },
        },
        "403": { description: "Admin access required", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/riders/{id}": {
    get: {
      tags: ["Riders"],
      summary: "Get rider by id (admin)",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/RiderId" }],
      responses: {
        ...riderResponse,
        "404": { description: "Not found", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
    patch: {
      tags: ["Riders"],
      summary: "Update rider (admin)",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/RiderId" }],
      requestBody: {
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                status: { type: "string", enum: ["pending", "active", "suspended", "blocked"] },
                isAvailable: { type: "boolean", example: true },
                isVerified: { type: "boolean", example: true },
                firstName: { type: "string", example: "Chidi" },
                lastName: { type: "string", example: "Eze" },
                phone: { type: "string", example: "+2348098765432" },
                email: { type: "string", example: "chidi.rider@example.com" },
              },
            },
          },
        },
      },
      responses: riderResponse,
    },
  },
  "/api/riders/{id}/status": {
    patch: {
      tags: ["Riders"],
      summary: "Update rider status (admin)",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/RiderId" }],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["status"],
              properties: {
                status: { type: "string", enum: ["active", "suspended", "blocked"], example: "suspended" },
              },
            },
          },
        },
      },
      responses: riderResponse,
    },
  },
};
