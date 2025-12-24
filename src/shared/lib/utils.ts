/**
 * Generate a 6-digit OTP
 * @returns 6-digit OTP string
 */
export const generateOTP = (): string => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

