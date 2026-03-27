/**
 * Email verification purposes
 */
export enum EmailVerificationPurpose {
  EMAIL_VERIFICATION = "Email verification",
  PASSWORD_RESET = "Password reset",
}

/**
 * Shipment lifecycle status
 */
export enum ShipmentStatus {
  PENDING = "pending",
  SCHEDULED = "scheduled",
  SEARCHING_RIDER = "searching_rider",
  /** Offer sent to a rider; waiting for accept/reject or deadline. */
  AWAITING_RIDER_RESPONSE = "awaiting_rider_response",
  RIDER_ASSIGNED = "rider_assigned",
  PICKED_UP = "picked_up",
  IN_TRANSIT = "in_transit",
  DELIVERED = "delivered",
  CANCELLED = "cancelled",
}

/**
 * Delivery timing type
 */
export enum DeliveryType {
  INSTANT = "instant",
  SCHEDULED = "scheduled",
}

/**
 * Payment status for a shipment
 */
export enum PaymentStatus {
  PENDING = "pending",
  PAID = "paid",
  FAILED = "failed",
}

/**
 * Rider account status
 */
export enum RiderStatus {
  PENDING = "pending",
  ACTIVE = "active",
  SUSPENDED = "suspended",
  BLOCKED = "blocked",
}

/**
 * In-app notification kinds
 */
export enum NotificationType {
  SHIPMENT_ASSIGNED = "shipment_assigned",
  RIDER_ACCEPTED_SHIPMENT = "rider_accepted_shipment",
  DELIVERY_COMPLETE = "delivery_complete",
}

