import { cookieSecurity } from "../components";

export const notificationPaths = {
  "/api/notifications": {
    get: {
      tags: ["Notifications"],
      summary: "List notifications for current user",
      security: cookieSecurity,
      parameters: [
        {
          name: "limit",
          in: "query",
          schema: { type: "integer", default: 50, maximum: 100 },
          description: "Max items (default 50, cap 100)",
        },
      ],
      responses: {
        "200": {
          description: "Notifications newest first",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { type: "array", items: { $ref: "#/components/schemas/Notification" } },
                },
              },
            },
          },
        },
        "401": { description: "Unauthorized", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/notifications/unread-count": {
    get: {
      tags: ["Notifications"],
      summary: "Unread notification count",
      security: cookieSecurity,
      responses: {
        "200": {
          description: "Count",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: {
                    type: "object",
                    properties: { count: { type: "integer", example: 3 } },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
  "/api/notifications/{id}/read": {
    patch: {
      tags: ["Notifications"],
      summary: "Mark one notification as read",
      security: cookieSecurity,
      parameters: [{ $ref: "#/components/parameters/NotificationId" }],
      responses: {
        "200": {
          description: "Updated notification",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { $ref: "#/components/schemas/Notification" },
                },
              },
            },
          },
        },
        "404": { description: "Not found", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/notifications/mark-all-read": {
    post: {
      tags: ["Notifications"],
      summary: "Mark all notifications as read",
      security: cookieSecurity,
      responses: {
        "200": {
          description: "Bulk update result",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: {
                    type: "object",
                    properties: { modified: { type: "integer", example: 5 } },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
};
