export const swaggerComponents = {
  securitySchemes: {
    cookieAuth: {
      type: "apiKey",
      in: "cookie",
      name: "token",
      description: "httpOnly JWT set by POST /api/auth/login. Use browser or send Cookie header in Postman.",
    },
  },
  schemas: {
    ApiError: {
      type: "object",
      properties: {
        success: { type: "boolean", example: false },
        message: { type: "string", example: "Authentication required" },
        code: { type: "string", example: "EMAIL_NOT_VERIFIED" },
      },
    },
    ApiSuccessMessage: {
      type: "object",
      properties: {
        success: { type: "boolean", example: true },
        message: { type: "string", example: "Operation completed" },
      },
    },
    ContactDetails: {
      type: "object",
      required: ["fullName", "address", "phone", "country", "state"],
      properties: {
        fullName: { type: "string", example: "Ada Okafor" },
        address: { type: "string", example: "12 Admiralty Way, Lekki" },
        phone: { type: "string", example: "+2348012345678" },
        country: { type: "string", example: "NG", description: "ISO 3166-1 alpha-2 country code" },
        state: {
          type: "string",
          example: "Lagos",
          description: "State or province name (for Nigeria, must match a known state)",
        },
      },
    },
    PackageDetails: {
      type: "object",
      required: ["type", "weight", "lengthCm", "widthCm", "heightCm", "quantity"],
      properties: {
        type: { type: "string", example: "parcel" },
        weight: { type: "number", example: 2.5 },
        lengthCm: { type: "number", minimum: 0, example: 30, description: "Package length in cm" },
        widthCm: { type: "number", minimum: 0, example: 20, description: "Package width in cm" },
        heightCm: { type: "number", minimum: 0, example: 15, description: "Package height in cm" },
        quantity: { type: "integer", example: 1 },
        note: { type: "string", example: "Handle with care" },
      },
    },
    TimelineEntry: {
      type: "object",
      properties: {
        status: { type: "string", example: "pending" },
        timestamp: { type: "string", format: "date-time", example: "2026-05-17T10:00:00.000Z" },
      },
    },
    Shipment: {
      type: "object",
      properties: {
        _id: { type: "string", example: "664a1b2c3d4e5f6789012345" },
        userId: { type: "string", example: "664a1b2c3d4e5f6789012340" },
        status: {
          type: "string",
          enum: [
            "pending",
            "scheduled",
            "searching_rider",
            "awaiting_rider_response",
            "rider_assigned",
            "picked_up",
            "in_transit",
            "delivered",
            "cancelled",
          ],
          example: "awaiting_rider_response",
        },
        deliveryType: { type: "string", enum: ["instant", "scheduled"], example: "instant" },
        price: { type: "number", example: 1250 },
        paymentStatus: { type: "string", enum: ["pending", "paid", "failed"], example: "pending" },
        paystackReference: { type: "string", example: "shp_507f1f77bcf86cd799439011_abc123" },
        paidAt: { type: "string", format: "date-time" },
        riderID: { type: "string", nullable: true, example: "664a1b2c3d4e5f6789012346" },
        senderDetails: { $ref: "#/components/schemas/ContactDetails" },
        recipientDetails: { $ref: "#/components/schemas/ContactDetails" },
        packageDetails: { $ref: "#/components/schemas/PackageDetails" },
        pickupWindowStart: { type: "string", format: "date-time", nullable: true },
        pickupWindowEnd: { type: "string", format: "date-time", nullable: true },
        pickupLongitude: {
          type: "number",
          nullable: true,
          description: "WGS84 longitude set at create time or geocoded from sender address during rider assignment",
        },
        pickupLatitude: {
          type: "number",
          nullable: true,
          description: "WGS84 latitude set at create time or geocoded from sender address during rider assignment",
        },
        recipientLongitude: { type: "number", nullable: true },
        recipientLatitude: { type: "number", nullable: true },
        timeline: {
          type: "array",
          items: { $ref: "#/components/schemas/TimelineEntry" },
        },
        createdByAdmin: {
          type: "boolean",
          example: false,
          description: "True when an admin created the shipment (sender shown as ADMIN to riders)",
        },
        deliveryProofUploadedAt: {
          type: "string",
          format: "date-time",
          nullable: true,
          description: "When the assigned rider uploaded a delivery photo",
        },
        senderConfirmedReceipt: {
          type: "boolean",
          example: false,
          description: "True when the client owner confirmed the recipient received the package",
        },
        senderConfirmedReceiptAt: {
          type: "string",
          format: "date-time",
          nullable: true,
        },
        hasDeliveryProof: {
          type: "boolean",
          example: false,
          description:
            "True when a delivery photo exists and/or the sender confirmed receipt. Required before mark delivered.",
        },
        deliveryProofImageUrl: {
          type: "string",
          format: "uri",
          nullable: true,
          description:
            "Presigned S3 read URL for the delivery photo (~1 hour expiry). Generated on read, not stored in the database.",
        },
        createdAt: { type: "string", format: "date-time" },
        updatedAt: { type: "string", format: "date-time" },
      },
    },
    AuthUser: {
      type: "object",
      properties: {
        id: { type: "string", example: "664a1b2c3d4e5f6789012340" },
        firstName: { type: "string", example: "Ada" },
        lastName: { type: "string", example: "Okafor" },
        email: { type: "string", example: "ada@example.com" },
        role: { type: "string", enum: ["client", "rider", "admin"], example: "client" },
      },
    },
    UserProfile: {
      type: "object",
      properties: {
        id: { type: "string" },
        firstName: { type: "string", example: "Ada" },
        lastName: { type: "string", example: "Okafor" },
        email: { type: "string", example: "ada@example.com" },
        phone: { type: "string", example: "+2348012345678" },
        role: { type: "string", enum: ["client", "rider", "admin"] },
        status: { type: "string", enum: ["active", "suspended", "blocked"] },
        isEmailVerified: { type: "boolean" },
        createdAt: { type: "string", format: "date-time" },
        updatedAt: { type: "string", format: "date-time" },
      },
    },
    RiderUserRef: {
      type: "object",
      properties: {
        _id: { type: "string" },
        firstName: { type: "string", example: "Chidi" },
        lastName: { type: "string", example: "Eze" },
        email: { type: "string", example: "chidi.rider@example.com" },
        phone: { type: "string", example: "+2348098765432" },
      },
    },
    Rider: {
      type: "object",
      properties: {
        _id: { type: "string", example: "664a1b2c3d4e5f6789012346" },
        userId: { $ref: "#/components/schemas/RiderUserRef" },
        status: { type: "string", enum: ["pending", "active", "suspended", "blocked"], example: "active" },
        isAvailable: {
          type: "boolean",
          example: true,
          description: "On duty when true; off duty when false. Does not lock after assignment — riders may hold multiple active shipments.",
        },
        isVerified: { type: "boolean", example: true },
        location: {
          type: "object",
          nullable: true,
          properties: {
            type: { type: "string", example: "Point" },
            coordinates: {
              type: "array",
              items: { type: "number" },
              example: [3.3792, 6.5244],
            },
          },
        },
        createdAt: { type: "string", format: "date-time" },
        updatedAt: { type: "string", format: "date-time" },
      },
    },
    Notification: {
      type: "object",
      properties: {
        _id: { type: "string", example: "664a1b2c3d4e5f6789012350" },
        userId: { type: "string" },
        type: {
          type: "string",
          enum: [
            "shipment_assigned",
            "shipment_offered",
            "rider_accepted_shipment",
            "delivery_complete",
            "complaint_submitted",
          ],
          example: "shipment_assigned",
        },
        title: { type: "string", example: "New shipment assigned" },
        message: { type: "string", example: "A shipment is waiting for your response." },
        read: { type: "boolean", example: false },
        relatedShipmentId: { type: "string", nullable: true, example: "664a1b2c3d4e5f6789012345" },
        relatedComplaintId: { type: "string", nullable: true, example: "664a1b2c3d4e5f6789012370" },
        createdAt: { type: "string", format: "date-time" },
        updatedAt: { type: "string", format: "date-time" },
      },
    },
    Feedback: {
      type: "object",
      properties: {
        _id: { type: "string", example: "664a1b2c3d4e5f6789012360" },
        clientUserId: { type: "string" },
        riderId: { type: "string" },
        shipmentId: { type: "string" },
        rating: { type: "integer", minimum: 1, maximum: 5, example: 5 },
        comment: { type: "string", example: "Fast and professional delivery." },
        riderName: { type: "string", example: "Chidi Eze" },
        createdAt: { type: "string", format: "date-time" },
        updatedAt: { type: "string", format: "date-time" },
      },
    },
    AdminClient: {
      type: "object",
      properties: {
        id: { type: "string", example: "664a1b2c3d4e5f6789012340" },
        firstName: { type: "string", example: "Ada" },
        lastName: { type: "string", example: "Okafor" },
        email: { type: "string", example: "ada@example.com" },
        phone: { type: "string", example: "+2348012345678" },
        status: { type: "string", enum: ["active", "suspended", "blocked"], example: "active" },
        isEmailVerified: { type: "boolean", example: true },
        createdAt: { type: "string", format: "date-time" },
        shipmentCount: { type: "integer", example: 12 },
      },
    },
    AdminClientStats: {
      type: "object",
      properties: {
        totalShipments: { type: "integer", example: 12 },
        activeShipments: { type: "integer", example: 2 },
        deliveredCount: { type: "integer", example: 9 },
        totalSpent: { type: "number", example: 11250 },
      },
    },
    AdminShipmentListItem: {
      type: "object",
      properties: {
        id: { type: "string" },
        status: { type: "string", example: "in_transit" },
        deliveryType: { type: "string", example: "instant" },
        price: { type: "number", example: 1250 },
        paymentStatus: { type: "string", enum: ["pending", "paid", "failed"], example: "pending" },
        paystackReference: { type: "string", example: "shp_507f1f77bcf86cd799439011_abc123" },
        paidAt: { type: "string", format: "date-time" },
        createdAt: { type: "string", format: "date-time" },
        assignmentLabel: { type: "string", example: "Assigned" },
        client: {
          type: "object",
          properties: {
            id: { type: "string" },
            firstName: { type: "string", example: "Ada" },
            lastName: { type: "string", example: "Okafor" },
            email: { type: "string" },
            phone: { type: "string" },
          },
        },
        rider: {
          type: "object",
          nullable: true,
          properties: {
            riderId: { type: "string" },
            firstName: { type: "string", example: "Chidi" },
            lastName: { type: "string", example: "Eze" },
            email: { type: "string" },
            phone: { type: "string" },
          },
        },
        hasDeliveryProof: {
          type: "boolean",
          example: false,
          description: "True when a delivery photo exists and/or the sender confirmed receipt",
        },
        deliveryProofUploadedAt: { type: "string", format: "date-time", nullable: true },
        senderConfirmedReceipt: { type: "boolean", example: false },
        senderConfirmedReceiptAt: { type: "string", format: "date-time", nullable: true },
        deliveryProofImageUrl: {
          type: "string",
          format: "uri",
          nullable: true,
          description: "Presigned S3 read URL (~1 hour expiry)",
        },
      },
    },
    AdminShipmentDetail: {
      allOf: [
        { $ref: "#/components/schemas/AdminShipmentListItem" },
        {
          type: "object",
          properties: {
            senderDetails: { $ref: "#/components/schemas/ContactDetails" },
            recipientDetails: { $ref: "#/components/schemas/ContactDetails" },
            packageDetails: { $ref: "#/components/schemas/PackageDetails" },
            timeline: {
              type: "array",
              items: { $ref: "#/components/schemas/TimelineEntry" },
            },
            pickupWindowStart: { type: "string", format: "date-time", nullable: true },
            pickupWindowEnd: { type: "string", format: "date-time", nullable: true },
            pickupLongitude: { type: "number", nullable: true },
            pickupLatitude: { type: "number", nullable: true },
            recipientLongitude: { type: "number", nullable: true },
            recipientLatitude: { type: "number", nullable: true },
            riderResponseDeadline: { type: "string", format: "date-time", nullable: true },
            declinedRiderCount: { type: "integer", example: 0 },
            createdByAdmin: { type: "boolean", example: false },
            updatedAt: { type: "string", format: "date-time" },
          },
        },
      ],
    },
    AdminShipmentExportItem: {
      allOf: [
        { $ref: "#/components/schemas/AdminShipmentListItem" },
        {
          type: "object",
          properties: {
            senderDetails: { $ref: "#/components/schemas/ContactDetails" },
            recipientDetails: { $ref: "#/components/schemas/ContactDetails" },
            packageDetails: { $ref: "#/components/schemas/PackageDetails" },
            timeline: {
              type: "array",
              items: { $ref: "#/components/schemas/TimelineEntry" },
            },
            pickupWindowStart: { type: "string", format: "date-time", nullable: true },
            pickupWindowEnd: { type: "string", format: "date-time", nullable: true },
            pickupLongitude: { type: "number", nullable: true },
            pickupLatitude: { type: "number", nullable: true },
            recipientLongitude: { type: "number", nullable: true },
            recipientLatitude: { type: "number", nullable: true },
            riderResponseDeadline: { type: "string", format: "date-time", nullable: true },
            declinedRiderCount: { type: "integer", example: 0 },
            updatedAt: { type: "string", format: "date-time" },
            paystackReference: { type: "string", nullable: true },
            paidAt: { type: "string", format: "date-time", nullable: true },
            deliveredAt: { type: "string", format: "date-time", nullable: true },
          },
        },
      ],
    },
    AdminShipmentExportResult: {
      type: "object",
      properties: {
        generatedAt: { type: "string", format: "date-time" },
        year: { type: "integer", example: 2026 },
        month: { type: "integer", minimum: 1, maximum: 12, nullable: true, example: 5 },
        label: { type: "string", example: "May 2026" },
        count: { type: "integer", example: 42 },
        availableYears: { type: "array", items: { type: "integer" }, example: [2026, 2025] },
        shipments: {
          type: "array",
          items: { $ref: "#/components/schemas/AdminShipmentExportItem" },
        },
      },
    },
    ShipmentTracking: {
      type: "object",
      properties: {
        shipmentId: { type: "string" },
        status: { type: "string", example: "in_transit" },
        pickup: {
          type: "object",
          nullable: true,
          properties: {
            longitude: { type: "number", example: 3.3792 },
            latitude: { type: "number", example: 6.5244 },
          },
        },
        recipient: {
          type: "object",
          nullable: true,
          properties: {
            longitude: { type: "number", example: 3.4219 },
            latitude: { type: "number", example: 6.4474 },
          },
        },
        rider: {
          type: "object",
          nullable: true,
          properties: {
            longitude: { type: "number", example: 3.4 },
            latitude: { type: "number", example: 6.5 },
          },
        },
        riderLocationUpdatedAt: { type: "string", format: "date-time", nullable: true },
      },
    },
    PublicShipmentStatus: {
      type: "object",
      properties: {
        shipmentId: { type: "string", example: "664a1b2c3d4e5f6789012345" },
        status: {
          type: "string",
          enum: [
            "pending",
            "scheduled",
            "searching_rider",
            "awaiting_rider_response",
            "rider_assigned",
            "picked_up",
            "in_transit",
            "delivered",
            "cancelled",
          ],
          example: "in_transit",
        },
        deliveryType: { type: "string", enum: ["instant", "scheduled"], example: "instant" },
        updatedAt: { type: "string", format: "date-time" },
      },
    },
    RevenueSummary: {
      type: "object",
      properties: {
        currency: { type: "string", example: "NGN" },
        totalEarned: { type: "number", example: 250000 },
        deliveredCount: { type: "integer", example: 48 },
        activeShipmentCount: { type: "integer", example: 6 },
        availableRidersCount: { type: "integer", example: 4 },
        monthly: {
          type: "array",
          items: {
            type: "object",
            properties: {
              yearMonth: { type: "string", example: "2026-05" },
              label: { type: "string", example: "May 26" },
              amount: { type: "number", example: 45000 },
            },
          },
        },
      },
    },
    RiderAddressBookEntry: {
      type: "object",
      properties: {
        role: { type: "string", enum: ["sender", "recipient"], example: "recipient" },
        fullName: { type: "string", example: "John Doe" },
        address: { type: "string", example: "45 Allen Ave, Ikeja" },
        phone: { type: "string", example: "+2348011111111" },
        lastSeenAt: { type: "string", format: "date-time" },
      },
    },
    Complaint: {
      type: "object",
      properties: {
        id: { type: "string", example: "664a1b2c3d4e5f6789012370" },
        userId: { type: "string", example: "664a1b2c3d4e5f6789012340" },
        reporterType: { type: "string", enum: ["client", "rider"], example: "client" },
        subject: { type: "string", example: "Late delivery" },
        message: { type: "string", example: "The rider arrived two hours late." },
        phone: { type: "string", example: "+2348012345678" },
        relatedShipmentId: { type: "string", nullable: true, example: "664a1b2c3d4e5f6789012345" },
        status: { type: "string", enum: ["open", "in_review", "resolved"], example: "open" },
        createdAt: { type: "string", format: "date-time" },
        updatedAt: { type: "string", format: "date-time" },
      },
    },
    ComplaintReporter: {
      type: "object",
      properties: {
        id: { type: "string" },
        firstName: { type: "string", example: "Ada" },
        lastName: { type: "string", example: "Okafor" },
        email: { type: "string", example: "ada@example.com" },
        phone: { type: "string", example: "+2348012345678" },
      },
    },
    AdminComplaint: {
      allOf: [
        { $ref: "#/components/schemas/Complaint" },
        {
          type: "object",
          properties: {
            reporter: { $ref: "#/components/schemas/ComplaintReporter" },
          },
        },
      ],
    },
    RiderMonthlyPerformance: {
      type: "object",
      properties: {
        yearMonth: { type: "string", example: "2026-05" },
        label: { type: "string", example: "May 26" },
        completedCount: { type: "integer", example: 8 },
      },
    },
    RiderCompletedOrder: {
      type: "object",
      properties: {
        id: { type: "string" },
        status: { type: "string", example: "delivered" },
        deliveryType: { type: "string", example: "instant" },
        price: { type: "number", example: 1250 },
        paymentStatus: { type: "string", example: "paid" },
        deliveredAt: { type: "string", format: "date-time" },
        createdAt: { type: "string", format: "date-time" },
        senderName: { type: "string", example: "Ada Okafor" },
        recipientName: { type: "string", example: "John Doe" },
        client: {
          type: "object",
          properties: {
            id: { type: "string" },
            firstName: { type: "string" },
            lastName: { type: "string" },
            email: { type: "string" },
          },
        },
      },
    },
    RiderPerformance: {
      type: "object",
      properties: {
        riderId: { type: "string", example: "664a1b2c3d4e5f6789012346" },
        totalCompleted: { type: "integer", example: 42 },
        monthly: {
          type: "array",
          items: { $ref: "#/components/schemas/RiderMonthlyPerformance" },
        },
        orders: {
          type: "array",
          items: { $ref: "#/components/schemas/RiderCompletedOrder" },
        },
      },
    },
    FinancialReports: {
      type: "object",
      properties: {
        currency: { type: "string", example: "NGN" },
        generatedAt: { type: "string", format: "date-time" },
        monthCount: { type: "integer", example: 12 },
        year: { type: "integer", example: 2026, description: "Present when scoped to a calendar year" },
        availableYears: {
          type: "array",
          items: { type: "integer" },
          example: [2026, 2025, 2024],
        },
        allTimeRevenue: { type: "number", example: 250000 },
        allTimeDeliveredCount: { type: "integer", example: 48 },
        periodTotalRevenue: { type: "number", example: 120000 },
        periodTotalDelivered: { type: "integer", example: 22 },
        periodAverageMonthlyRevenue: { type: "number", example: 10000 },
        monthly: {
          type: "array",
          items: {
            type: "object",
            properties: {
              yearMonth: { type: "string", example: "2026-05" },
              label: { type: "string", example: "May 2026" },
              revenue: { type: "number", example: 45000 },
              deliveredCount: { type: "integer", example: 8 },
              averageOrderValue: { type: "number", example: 5625 },
              changeFromPreviousPct: { type: "integer", nullable: true, example: 12 },
            },
          },
        },
      },
    },
    MonthlyFinancialDelivery: {
      type: "object",
      properties: {
        id: { type: "string" },
        price: { type: "number", example: 5000 },
        paymentStatus: { type: "string", example: "paid" },
        deliveryType: { type: "string", example: "instant" },
        deliveredAt: { type: "string", format: "date-time" },
        createdAt: { type: "string", format: "date-time" },
        senderName: { type: "string", example: "Jane Sender" },
        recipientName: { type: "string", example: "John Recipient" },
        client: {
          type: "object",
          properties: {
            id: { type: "string" },
            firstName: { type: "string" },
            lastName: { type: "string" },
            email: { type: "string" },
          },
        },
        rider: {
          type: "object",
          nullable: true,
          properties: {
            riderId: { type: "string" },
            firstName: { type: "string" },
            lastName: { type: "string" },
            email: { type: "string" },
            phone: { type: "string" },
          },
        },
      },
    },
    MonthlyFinancialReportDetail: {
      type: "object",
      properties: {
        yearMonth: { type: "string", example: "2026-05" },
        label: { type: "string", example: "May 2026" },
        revenue: { type: "number", example: 45000 },
        deliveredCount: { type: "integer", example: 8 },
        averageOrderValue: { type: "number", example: 5625 },
        deliveries: {
          type: "array",
          items: { $ref: "#/components/schemas/MonthlyFinancialDelivery" },
        },
      },
    },
  },
  parameters: {
    ShipmentId: {
      name: "id",
      in: "path",
      required: true,
      schema: { type: "string", example: "664a1b2c3d4e5f6789012345" },
    },
    RiderId: {
      name: "id",
      in: "path",
      required: true,
      schema: { type: "string", example: "664a1b2c3d4e5f6789012346" },
    },
    NotificationId: {
      name: "id",
      in: "path",
      required: true,
      schema: { type: "string", example: "664a1b2c3d4e5f6789012350" },
    },
    ClientId: {
      name: "id",
      in: "path",
      required: true,
      schema: { type: "string", example: "664a1b2c3d4e5f6789012340" },
    },
    ComplaintId: {
      name: "id",
      in: "path",
      required: true,
      schema: { type: "string", example: "664a1b2c3d4e5f6789012370" },
    },
  },
};

export const cookieSecurity = [{ cookieAuth: [] }];
