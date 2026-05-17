import { cookieSecurity } from "../components";

export const adminPaths = {
  "/api/admin/revenue": {
    get: {
      tags: ["Admin"],
      summary: "Revenue summary (admin)",
      security: cookieSecurity,
      parameters: [
        {
          name: "months",
          in: "query",
          schema: { type: "integer", default: 12, minimum: 3, maximum: 24 },
          description: "Number of calendar months in chart series",
        },
      ],
      responses: {
        "200": {
          description: "Revenue dashboard data",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { $ref: "#/components/schemas/RevenueSummary" },
                },
              },
            },
          },
        },
        "403": { description: "Admin access required", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/admin/financial-reports": {
    get: {
      tags: ["Admin"],
      summary: "Monthly financial reports (admin)",
      security: cookieSecurity,
      parameters: [
        {
          name: "months",
          in: "query",
          schema: { type: "integer", default: 12, minimum: 3, maximum: 36 },
          description: "Number of calendar months to include",
        },
      ],
      responses: {
        "200": {
          description: "Monthly financial report series",
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
                      generatedAt: { type: "string", format: "date-time" },
                      monthCount: { type: "integer" },
                      allTimeRevenue: { type: "number" },
                      allTimeDeliveredCount: { type: "integer" },
                      periodTotalRevenue: { type: "number" },
                      periodTotalDelivered: { type: "integer" },
                      periodAverageMonthlyRevenue: { type: "number" },
                      monthly: {
                        type: "array",
                        items: {
                          type: "object",
                          properties: {
                            yearMonth: { type: "string", example: "2026-05" },
                            label: { type: "string", example: "May 2026" },
                            revenue: { type: "number" },
                            deliveredCount: { type: "integer" },
                            averageOrderValue: { type: "number" },
                            changeFromPreviousPct: { type: "integer", nullable: true },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        "403": { description: "Admin access required", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/admin/available-riders": {
    get: {
      tags: ["Admin"],
      summary: "List riders available for assignment",
      security: cookieSecurity,
      responses: {
        "200": {
          description: "Available riders",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        riderId: { type: "string" },
                        firstName: { type: "string", example: "Chidi" },
                        lastName: { type: "string", example: "Eze" },
                        email: { type: "string" },
                        phone: { type: "string" },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
  "/api/admin/shipments/bulk": {
    post: {
      tags: ["Admin"],
      summary: "Bulk create shipments for a client and assign riders",
      security: cookieSecurity,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["clientId", "defaultRiderId", "shipments"],
              properties: {
                clientId: { type: "string" },
                defaultRiderId: { type: "string" },
                shipments: {
                  type: "array",
                  maxItems: 20,
                  items: {
                    type: "object",
                    required: ["deliveryType", "senderDetails", "recipientDetails", "packageDetails"],
                    properties: {
                      deliveryType: { type: "string", enum: ["instant", "scheduled"] },
                      riderId: { type: "string", description: "Optional per-row rider override" },
                      senderDetails: { $ref: "#/components/schemas/ContactDetails" },
                      recipientDetails: { $ref: "#/components/schemas/ContactDetails" },
                      packageDetails: { $ref: "#/components/schemas/PackageDetails" },
                      pickupWindowStart: { type: "string", format: "date-time" },
                      pickupWindowEnd: { type: "string", format: "date-time" },
                      pickupLongitude: { type: "number" },
                      pickupLatitude: { type: "number" },
                    },
                  },
                },
              },
            },
          },
        },
      },
      responses: {
        "200": {
          description: "Per-row create/assign results (partial success allowed)",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string" },
                  data: {
                    type: "object",
                    properties: {
                      results: {
                        type: "array",
                        items: {
                          type: "object",
                          properties: {
                            index: { type: "integer" },
                            success: { type: "boolean" },
                            shipmentId: { type: "string" },
                            error: { type: "string" },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        "400": { description: "Validation error", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/admin/shipments": {
    get: {
      tags: ["Admin"],
      summary: "List all shipments (admin)",
      security: cookieSecurity,
      parameters: [
        { name: "status", in: "query", schema: { type: "string", example: "in_transit" } },
        { name: "limit", in: "query", schema: { type: "integer", default: 100, maximum: 200 } },
      ],
      responses: {
        "200": {
          description: "Shipment list",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { type: "array", items: { $ref: "#/components/schemas/AdminShipmentListItem" } },
                },
              },
            },
          },
        },
      },
    },
  },
  "/api/admin/shipments/{id}/assign": {
    patch: {
      tags: ["Admin"],
      summary: "Assign shipment to available rider",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/ShipmentId" }],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["riderId"],
              properties: {
                riderId: { type: "string", example: "664a1b2c3d4e5f6789012346" },
              },
            },
          },
        },
      },
      responses: {
        "200": {
          description: "Assignment pending rider acceptance",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string", example: "Rider assigned; awaiting rider acceptance" },
                  data: { $ref: "#/components/schemas/AdminShipmentListItem" },
                },
              },
            },
          },
        },
        "400": { description: "Rider not available or invalid state", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "404": { description: "Not found", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/admin/shipments/{id}": {
    get: {
      tags: ["Admin"],
      summary: "Get shipment detail (admin)",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/ShipmentId" }],
      responses: {
        "200": {
          description: "Full shipment with client and rider",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { $ref: "#/components/schemas/AdminShipmentListItem" },
                },
              },
            },
          },
        },
        "404": { description: "Not found", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/admin/clients": {
    get: {
      tags: ["Admin"],
      summary: "Search/list clients",
      security: cookieSecurity,
      parameters: [
        { name: "q", in: "query", schema: { type: "string", example: "ada@example.com" }, description: "Search name, email, phone" },
        { name: "limit", in: "query", schema: { type: "integer", default: 50, maximum: 100 } },
      ],
      responses: {
        "200": {
          description: "Client list",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { type: "array", items: { $ref: "#/components/schemas/AdminClient" } },
                },
              },
            },
          },
        },
      },
    },
  },
  "/api/admin/clients/{id}/activity": {
    get: {
      tags: ["Admin"],
      summary: "Client activity (shipments + feedback)",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/ClientId" }],
      responses: {
        "200": {
          description: "Activity history",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: {
                    type: "object",
                    properties: {
                      shipments: {
                        type: "array",
                        items: {
                          type: "object",
                          properties: {
                            id: { type: "string" },
                            status: { type: "string" },
                            deliveryType: { type: "string" },
                            price: { type: "number" },
                            paymentStatus: { type: "string" },
                            createdAt: { type: "string", format: "date-time" },
                            recipientName: { type: "string", example: "John Doe" },
                          },
                        },
                      },
                      feedback: {
                        type: "array",
                        items: {
                          type: "object",
                          properties: {
                            id: { type: "string" },
                            shipmentId: { type: "string" },
                            rating: { type: "integer" },
                            comment: { type: "string" },
                            createdAt: { type: "string", format: "date-time" },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        "404": { description: "Client not found", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/admin/clients/{id}/status": {
    patch: {
      tags: ["Admin"],
      summary: "Update client account status",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/ClientId" }],
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
      responses: {
        "200": {
          description: "Updated client",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string", example: "Client status updated" },
                  data: {
                    allOf: [
                      { $ref: "#/components/schemas/AdminClient" },
                      {
                        type: "object",
                        properties: { stats: { $ref: "#/components/schemas/AdminClientStats" } },
                      },
                    ],
                  },
                },
              },
            },
          },
        },
        "404": { description: "Client not found", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/admin/clients/{id}": {
    get: {
      tags: ["Admin"],
      summary: "Get client profile and stats",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/ClientId" }],
      responses: {
        "200": {
          description: "Client detail",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: {
                    allOf: [
                      { $ref: "#/components/schemas/AdminClient" },
                      {
                        type: "object",
                        properties: { stats: { $ref: "#/components/schemas/AdminClientStats" } },
                      },
                    ],
                  },
                },
              },
            },
          },
        },
        "404": { description: "Not found", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
};
