export interface ISmsProvider {
  /**
   * Sends a one-time verification passcode (OTP) to a destination phone number.
   * @param to Phone number in E.164 format (e.g. +14155552671)
   * @param otp 6-digit code
   */
  sendOtp(to: string, otp: string): Promise<boolean>;

  /**
   * Sends a generic SMS notification or alert.
   */
  sendSms(to: string, message: string): Promise<boolean>;
}
