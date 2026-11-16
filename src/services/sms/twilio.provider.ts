import twilio from 'twilio';
import { ISmsProvider } from './sms.interface.js';
import { config } from '../../config/env.js';

export class TwilioSmsProvider implements ISmsProvider {
  private client: twilio.Twilio | null = null;

  constructor() {
    if (
      config.TWILIO_ACCOUNT_SID &&
      config.TWILIO_ACCOUNT_SID.startsWith('AC') &&
      config.TWILIO_AUTH_TOKEN &&
      !config.TWILIO_ACCOUNT_SID.includes('00000000000000000000000000000000')
    ) {
      this.client = twilio(config.TWILIO_ACCOUNT_SID, config.TWILIO_AUTH_TOKEN);
    }
  }

  async sendOtp(to: string, otp: string): Promise<boolean> {
    const message = `Your Central Gaming security verification code is: ${otp}. Valid for 5 minutes. Do not share.`;
    return this.sendSms(to, message);
  }

  async sendSms(to: string, message: string): Promise<boolean> {
    if (!this.client || config.NODE_ENV === 'test' || !config.TWILIO_PHONE_NUMBER) {
      console.log(`[Dev Mock SMS] To: ${to} | Body: ${message}`);
      return true;
    }

    try {
      const response = await this.client.messages.create({
        body: message,
        from: config.TWILIO_PHONE_NUMBER,
        to,
      });

      return !!response.sid;
    } catch (err) {
      console.error('Twilio SMS delivery failure:', (err as Error).message);
      return false;
    }
  }
}
