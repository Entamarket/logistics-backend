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
