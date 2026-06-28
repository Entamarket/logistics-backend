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
      description:
        "For **instant** deliveries, `pickupLongitude` and `pickupLatitude` are optional. When omitted, the sender address is geocoded at rider assignment to find the nearest rider. When provided, both coordinates must be sent together. Scheduled deliveries use `pickupWindowStart` and `pickupWindowEnd` instead.",
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
                pickupWindowStart: {
                  type: "string",
                  format: "date-time",
                  example: "2026-05-18T14:00:00.000Z",
                  description: "Required for scheduled delivery (with pickupWindowEnd)",
                },
                pickupWindowEnd: {
                  type: "string",
                  format: "date-time",
                  example: "2026-05-18T16:00:00.000Z",
                  description: "Required for scheduled delivery (with pickupWindowStart)",
                },
                pickupLongitude: {
                  type: "number",
                  example: 3.3792,
                  description:
                    "Optional for instant delivery. WGS84 longitude for rider matching; omit to use geocoded sender address.",
                },
                pickupLatitude: {
                  type: "number",
                  example: 6.5244,
                  description:
                    "Optional for instant delivery. WGS84 latitude for rider matching; omit to use geocoded sender address.",
                },
                recipientLongitude: {
                  type: "number",
                  example: 3.4219,
                  description: "Optional drop-off longitude; must be provided with recipientLatitude.",
                },
                recipientLatitude: {
                  type: "number",
                  example: 6.4474,
                  description: "Optional drop-off latitude; must be provided with recipientLongitude.",
                },
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
      summary: "Verify Paystack payment and fulfill shipment (assign nearest rider if instant)",
      description:
        "For instant shipments, offers the nearest on-duty rider using pickup GPS coordinates when present, otherwise geocodes the sender address. Active jobs do not block new offers.",
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
  "/api/shipments/track/{id}": {
    get: {
      tags: ["Shipments"],
      summary: "Public shipment status lookup (no auth)",
      description:
        "Returns the current shipment status for the landing-page tracker. Accepts the full MongoDB shipment id or the 8-character reference shown in the dashboard. Does not expose addresses, pricing, or contact details.",
      parameters: [
        {
          name: "id",
          in: "path",
          required: true,
          schema: { type: "string", example: "664a1b2c3d4e5f6789012345" },
          description: "Full shipment id or 8-character reference (with or without #)",
        },
      ],
      responses: {
        "200": {
          description: "Current status",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { $ref: "#/components/schemas/PublicShipmentStatus" },
                },
              },
            },
          },
        },
        "400": {
          description: "Ambiguous short reference",
          content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } },
        },
        "404": { description: "Not found", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
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
      description:
        "Reassigns to the next nearest rider using pickup GPS when set, otherwise geocoded sender address.",
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
