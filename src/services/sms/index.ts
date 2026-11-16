import { ISmsProvider } from './sms.interface.js';
import { TwilioSmsProvider } from './twilio.provider.js';

// Clean factory export: you can swap this with an MSG91Provider or AWSSnsProvider at any time
export const smsProvider: ISmsProvider = new TwilioSmsProvider();
export * from './sms.interface.js';
