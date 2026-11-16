import { Resend } from 'resend';
import { config } from '../config/env.js';

export class EmailService {
  private static resend = new Resend(config.RESEND_API_KEY);

  /**
   * Sends transactional registration or password reset OTP.
   */
  static async sendOtpEmail(to: string, otp: string, purpose: 'register' | 'password_reset'): Promise<boolean> {
    const isRegister = purpose === 'register';
    const subject = isRegister
      ? 'Verify Your Central Gaming Account'
      : 'Password Reset Verification Code';

    const actionText = isRegister
      ? 'verifying your new game account'
      : 'resetting your password';

    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 580px; margin: 0 auto; background: #0f172a; color: #f8fafc; border-radius: 8px; padding: 32px;">
        <h1 style="color: #38bdf8; margin-top: 0; font-size: 24px;">Central Gaming Identity</h1>
        <p style="font-size: 16px; line-height: 1.5; color: #cbd5e1;">
          You are receiving this code for ${actionText}. This one-time password expires in <strong>${isRegister ? '5' : '10'} minutes</strong>.
        </p>
        <div style="margin: 28px 0; text-align: center;">
          <span style="display: inline-block; font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #38bdf8; background: #1e293b; padding: 16px 28px; border-radius: 8px; border: 1px solid #334155;">
            ${otp}
          </span>
        </div>
        <p style="font-size: 13px; color: #94a3b8; line-height: 1.4;">
          Security Alert: If you did not request this code, please ignore this email or review your account security immediately. Do not share this code with anyone.
        </p>
      </div>
    `;

    const text = `Your verification code is: ${otp}\nThis code expires in ${isRegister ? '5' : '10'} minutes. If you did not request this, please ignore.`;

    try {
      if (config.NODE_ENV === 'test' || config.RESEND_API_KEY.includes('placeholder')) {
        console.log(`[Dev Mock Email] To: ${to} | Subject: ${subject} | Code: ${otp}`);
        return true;
      }

      const response = await this.resend.emails.send({
        from: config.RESEND_FROM_EMAIL,
        to,
        subject,
        html,
        text,
      });

      return !response.error;
    } catch (err) {
      console.error('Failed to send OTP email via Resend:', (err as Error).message);
      return false;
    }
  }

  /**
   * Sends security alert when a login is detected from a new IP or device.
   * Includes one-click link to revoke all active sessions.
   */
  static async sendNewDeviceLoginAlert(params: {
    to: string;
    username: string;
    ipAddress: string;
    deviceFingerprint?: string;
    revokeToken: string;
  }): Promise<boolean> {
    const revokeUrl = `${config.FRONTEND_URL}/auth/revoke-sessions?token=${params.revokeToken}`;
    const subject = 'Security Alert: New Sign-In Detected';

    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 580px; margin: 0 auto; background: #0f172a; color: #f8fafc; border-radius: 8px; padding: 32px;">
        <h1 style="color: #f43f5e; margin-top: 0; font-size: 22px;">New Sign-In Alert</h1>
        <p style="font-size: 15px; color: #cbd5e1;">
          Hello <strong>${params.username}</strong>, your account was just accessed from a new device or IP address.
        </p>
        <div style="background: #1e293b; padding: 18px; border-radius: 6px; margin: 20px 0; font-size: 14px; line-height: 1.6; border: 1px solid #334155;">
          <div><strong>IP Address:</strong> ${params.ipAddress}</div>
          <div><strong>Device / Client:</strong> ${params.deviceFingerprint || 'Unknown Client'}</div>
          <div><strong>Time:</strong> ${new Date().toUTCString()}</div>
        </div>
        <p style="font-size: 14px; color: #cbd5e1;">
          If this was you, you can safely ignore this email. If you do not recognize this activity, protect your account immediately:
        </p>
        <div style="text-align: center; margin: 26px 0;">
          <a href="${revokeUrl}" style="background: #e11d48; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: bold; display: inline-block;">
            Revoke All Active Sessions
          </a>
        </div>
      </div>
    `;

    const text = `New sign-in detected for ${params.username} from IP: ${params.ipAddress}. If this was not you, revoke sessions immediately: ${revokeUrl}`;

    try {
      if (config.NODE_ENV === 'test' || config.RESEND_API_KEY.includes('placeholder')) {
        console.log(`[Dev Mock Email] New device login alert sent to ${params.to}`);
        return true;
      }

      const response = await this.resend.emails.send({
        from: config.RESEND_FROM_EMAIL,
        to: params.to,
        subject,
        html,
        text,
      });

      return !response.error;
    } catch (err) {
      console.error('Failed to send login alert email:', (err as Error).message);
      return false;
    }
  }

  /**
   * Sends confirmation when password has been successfully reset.
   */
  static async sendPasswordChangedConfirmation(to: string, username: string): Promise<boolean> {
    const subject = 'Your Password Has Been Changed';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 580px; margin: 0 auto; background: #0f172a; color: #f8fafc; border-radius: 8px; padding: 32px;">
        <h2 style="color: #38bdf8; margin-top: 0;">Password Changed Successfully</h2>
        <p style="color: #cbd5e1; font-size: 15px;">
          Hello ${username}, the password for your Central Gaming account has been updated.
        </p>
        <p style="color: #cbd5e1; font-size: 14px;">
          All previous active sessions have been invalidated as a security precaution.
        </p>
      </div>
    `;

    try {
      if (config.NODE_ENV === 'test' || config.RESEND_API_KEY.includes('placeholder')) {
        console.log(`[Dev Mock Email] Password changed confirmation sent to ${to}`);
        return true;
      }

      await this.resend.emails.send({
        from: config.RESEND_FROM_EMAIL,
        to,
        subject,
        html,
        text: `Your password has been changed successfully. All previous sessions have been revoked.`,
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Sends batch game update announcements via Resend.
   */
  static async sendMarketingBatch(
    recipients: string[],
    subject: string,
    htmlContent: string,
    textContent: string
  ): Promise<{ sent: number; failed: number }> {
    if (recipients.length === 0) {
      return { sent: 0, failed: 0 };
    }

    if (config.NODE_ENV === 'test' || config.RESEND_API_KEY.includes('placeholder')) {
      console.log(`[Dev Mock Email] Marketing announcement sent to ${recipients.length} recipients.`);
      return { sent: recipients.length, failed: 0 };
    }

    // Chunk in batches of 100 (Resend batch limit)
    const BATCH_SIZE = 100;
    let sent = 0;
    let failed = 0;

    for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
      const chunk = recipients.slice(i, i + BATCH_SIZE);
      const emailBatch = chunk.map((to) => ({
        from: config.RESEND_FROM_EMAIL,
        to,
        subject,
        html: htmlContent,
        text: textContent,
      }));

      try {
        const res = await this.resend.batch.send(emailBatch);
        if (res.data) {
          sent += chunk.length;
        } else {
          failed += chunk.length;
        }
      } catch (err) {
        console.error('Batch email send error:', (err as Error).message);
        failed += chunk.length;
      }
    }

    return { sent, failed };
  }
}
