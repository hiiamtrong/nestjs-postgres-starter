import { Cache, CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject, Injectable } from '@nestjs/common';
import { AppConfigService } from 'src/shared/configs/config.service';
import {
  CACHE_KEY_EMAIL_OTP,
  CACHE_KEY_PHONE_OTP,
} from 'src/shared/constants/cache';
import { CacheUtils } from 'src/shared/utils/cache';

@Injectable()
export class OtpService {
  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly config: AppConfigService,
  ) {}

  generateOtp(): string {
    return '123456';
    const digits = '0123456789';
    let otp = '';
    const len = digits.length;
    for (let i = 0; i < this.config.otp.length; i++) {
      otp += digits[Math.floor(Math.random() * len)];
    }

    return otp;
  }

  async sendPhoneOtp(phone: string): Promise<void> {
    const otp = this.generateOtp();
    // Todo: Send OTP to the phone number
    await this.cacheManager.set(
      CacheUtils.getCacheKey(CACHE_KEY_PHONE_OTP, phone),
      otp,
      this.config.otp.ttl,
    );
  }

  async verifyPhoneOtp(phone: string, otp: string): Promise<boolean> {
    const cachedOtp = await this.cacheManager.get<string>(
      CacheUtils.getCacheKey(CACHE_KEY_PHONE_OTP, phone),
    );
    return cachedOtp === otp;
  }

  async clearPhoneOtp(phone: string): Promise<void> {
    await this.cacheManager.del(
      CacheUtils.getCacheKey(CACHE_KEY_PHONE_OTP, phone),
    );
  }

  async sendEmailOtp(email: string) {
    const otp = this.generateOtp();

    await this.cacheManager.set(
      CacheUtils.getCacheKey(CACHE_KEY_EMAIL_OTP, email),
      otp,
      this.config.otp.ttl,
    );
  }

  async verifyEmailOtp(email: string, otp: string): Promise<boolean> {
    const cachedOtp = await this.cacheManager.get<string>(
      CacheUtils.getCacheKey(CACHE_KEY_EMAIL_OTP, email),
    );
    return cachedOtp === otp;
  }

  async clearEmailOtp(email: string): Promise<void> {
    await this.cacheManager.del(
      CacheUtils.getCacheKey(CACHE_KEY_EMAIL_OTP, email),
    );
  }
}
