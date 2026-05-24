import { cookieSecurity } from "../components";

const shipmentResponses = {
  "200": {
    description: "Shipment data",
    content: {
      "application/json": {
        schema: {
          type: "object",
          properties: {
            success: { type: "boolean", example: true },
            message: { type: "string" },
            data: { $ref: "#/components/schemas/Shipment" },
          },
        },
      },
    },
  },
};

export const shipmentPaths = {
  "/api/shipments": {
    post: {
      tags: ["Shipments"],
      summary: "Create a shipment (client; payment pending until Paystack succeeds)",
      security: cookieSecurity,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["deliveryType", "senderDetails", "recipientDetails", "packageDetails"],
              properties: {
                deliveryType: { type: "string", enum: ["instant", "scheduled"], example: "instant" },
                senderDetails: { $ref: "#/components/schemas/ContactDetails" },
                recipientDetails: { $ref: "#/components/schemas/ContactDetails" },
                packageDetails: { $ref: "#/components/schemas/PackageDetails" },
                pickupWindowStart: { type: "string", format: "date-time", example: "2026-05-18T14:00:00.000Z" },
                pickupWindowEnd: { type: "string", format: "date-time", example: "2026-05-18T16:00:00.000Z" },
                pickupLongitude: { type: "number", example: 3.3792 },
                pickupLatitude: { type: "number", example: 6.5244 },
                recipientLongitude: { type: "number", example: 3.4219 },
                recipientLatitude: { type: "number", example: 6.4474 },
              },
            },
          },
        },
      },
      responses: {
        "201": shipmentResponses["200"],
        "400": { description: "Validation error", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "401": { description: "Unauthorized", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "403": { description: "Account suspended", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
    get: {
      tags: ["Shipments"],
      summary: "List shipments for current user (client)",
      security: cookieSecurity,
      responses: {
        "200": {
          description: "Shipment list",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { type: "array", items: { $ref: "#/components/schemas/Shipment" } },
                },
              },
            },
          },
        },
        "401": { description: "Unauthorized", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/shipments/{id}/payment/initialize": {
    post: {
      tags: ["Shipments"],
      summary: "Initialize Paystack payment for a shipment",
      security: cookieSecurity,
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      responses: {
        "200": {
          description: "Paystack initialize data for Inline popup",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: {
                    type: "object",
                    properties: {
                      accessCode: { type: "string" },
                      reference: { type: "string" },
                      amountKobo: { type: "number", example: 615000 },
                      publicKey: { type: "string" },
                      email: { type: "string", format: "email" },
                      alreadyPaid: { type: "boolean", description: "True when a prior reference was already successful" },
                    },
                  },
                },
              },
            },
          },
        },
        "400": { description: "Validation error", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "401": { description: "Unauthorized", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/shipments/{id}/payment/verify": {
    post: {
      tags: ["Shipments"],
      summary: "Verify Paystack payment and fulfill shipment (assign rider if instant)",
      security: cookieSecurity,
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["reference"],
              properties: { reference: { type: "string" } },
            },
          },
        },
      },
      responses: {
        "200": shipmentResponses["200"],
        "400": { description: "Verification failed", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "401": { description: "Unauthorized", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/shipments/estimate-price": {
    post: {
      tags: ["Shipments"],
      summary: "Estimate shipment price (base + distance + weight + volume tier)",
      security: cookieSecurity,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["senderDetails", "recipientDetails", "weight", "lengthCm", "widthCm", "heightCm"],
              properties: {
                senderDetails: { $ref: "#/components/schemas/ContactDetails" },
                recipientDetails: { $ref: "#/components/schemas/ContactDetails" },
                weight: { type: "number", minimum: 0, example: 7 },
                lengthCm: { type: "number", minimum: 0, example: 30 },
                widthCm: { type: "number", minimum: 0, example: 30 },
                heightCm: { type: "number", minimum: 0, example: 30 },
              },
            },
          },
        },
      },
      responses: {
        "200": {
          description: "Price breakdown",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: {
                    type: "object",
                    properties: {
                      currency: { type: "string", example: "NGN" },
                      baseFee: { type: "number", example: 1500 },
                      distanceMeters: { type: "number", example: 8500 },
                      distanceKm: { type: "number", example: 9 },
                      distanceFee: { type: "number", example: 1350 },
                      weightFee: { type: "number", example: 0 },
                      volumeCm3: { type: "number", example: 27000 },
                      dimensionCategory: { type: "string", enum: ["small", "medium", "large", "extraLarge"], example: "medium" },
                      dimensionFee: { type: "number", example: 500 },
                      total: { type: "number", example: 3350 },
                    },
                  },
                },
              },
            },
          },
        },
        "400": { description: "Validation or geocoding error", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "401": { description: "Unauthorized", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/shipments/rider/me": {
    get: {
      tags: ["Shipments"],
      summary: "List shipments for logged-in rider",
      security: cookieSecurity,
      parameters: [
        {
          name: "scope",
          in: "query",
          schema: { type: "string", enum: ["active", "history", "all"], default: "active" },
          description: "active = in progress; history = delivered/cancelled; all = any assigned",
        },
      ],
      responses: {
        "200": {
          description: "Rider shipments",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { type: "array", items: { $ref: "#/components/schemas/Shipment" } },
                },
              },
            },
          },
        },
        "403": { description: "Rider access required", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "404": { description: "Rider profile not found", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/shipments/rider/me/address-book": {
    get: {
      tags: ["Shipments"],
      summary: "Rider address book from assigned shipments",
      security: cookieSecurity,
      responses: {
        "200": {
          description: "Deduped contacts",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { type: "array", items: { $ref: "#/components/schemas/RiderAddressBookEntry" } },
                },
              },
            },
          },
        },
        "403": { description: "Rider access required", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/shipments/{id}/tracking": {
    get: {
      tags: ["Shipments"],
      summary: "Track shipment (owner only)",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/ShipmentId" }],
      responses: {
        "200": {
          description: "Tracking snapshot",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { $ref: "#/components/schemas/ShipmentTracking" },
                },
              },
            },
          },
        },
        "403": { description: "Not shipment owner", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "404": { description: "Not found", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/shipments/{id}/picked-up": {
    patch: {
      tags: ["Shipments"],
      summary: "Mark picked up (assigned rider)",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/ShipmentId" }],
      responses: shipmentResponses,
    },
  },
  "/api/shipments/{id}/in-transit": {
    patch: {
      tags: ["Shipments"],
      summary: "Mark in transit (assigned rider)",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/ShipmentId" }],
      responses: shipmentResponses,
    },
  },
  "/api/shipments/{id}/rider/accept": {
    patch: {
      tags: ["Shipments"],
      summary: "Accept rider offer",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/ShipmentId" }],
      responses: shipmentResponses,
    },
  },
  "/api/shipments/{id}/rider/reject": {
    patch: {
      tags: ["Shipments"],
      summary: "Reject rider offer",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/ShipmentId" }],
      responses: shipmentResponses,
    },
  },
  "/api/shipments/{id}/delivered": {
    patch: {
      tags: ["Shipments"],
      summary: "Mark delivered (assigned rider or admin)",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/ShipmentId" }],
      responses: shipmentResponses,
    },
  },
};
