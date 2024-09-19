import * as dotenv from 'dotenv';
import * as Joi from 'joi';
import { get, map } from 'lodash';
dotenv.config();

export interface EnvConfig {
  APP_ENV: string;
  APP_PORT: number;
  APP_HOST: string;

  DB_HOST: string;
  DB_PORT: number;
  DB_NAME: string;
  DB_USER: string;
  DB_PASS: string;

  REDIS_HOST: string;
  REDIS_PORT: number;
  REDIS_PASS?: string;

  JWT_ACCESS_TOKEN_EXP_IN_SEC: number;
  JWT_REFRESH_TOKEN_EXP_IN_SEC: number;
  JWT_PUBLIC_KEY_BASE64: string;
  JWT_PRIVATE_KEY_BASE64: string;

  DEFAULT_ADMIN_USER_PASSWORD: string;

  OTP_TTL_SEC: number;
  OTP_LENGTH: number;
}

export interface AppConfig {
  env: string;
  port: number;
  host: string;
}

export interface DBConfig {
  host: string;
  port: number;
  name: string;
  user: string;
  pass: string;
}

export interface RedisConfig {
  host: string;
  port: number;
  pass?: string;
}

export interface JWTConfig {
  accessTokenExpInSec: number;
  refreshTokenExpInSec: number;
  publicKey: string;
  privateKey: string;
}

export interface OTPConfig {
  length: number;
  ttl: number;
}

export class AppConfigService {
  private readonly envConfig: EnvConfig;
  private readonly validationScheme = {
    APP_ENV: Joi.string()
      .valid('development', 'production', 'test')
      .default('development'),
    APP_PORT: Joi.number().required(),
    APP_HOST: Joi.string().default('localhost'),

    DB_HOST: Joi.string().required(),
    DB_PORT: Joi.number().optional(),
    DB_NAME: Joi.string().required(),
    DB_USER: Joi.string().required(),
    DB_PASS: Joi.string().required(),

    REDIS_HOST: Joi.string().required(),
    REDIS_PORT: Joi.number().required(),
    REDIS_PASS: Joi.string().optional(),

    JWT_PUBLIC_KEY_BASE64: Joi.string().required(),
    JWT_PRIVATE_KEY_BASE64: Joi.string().required(),
    JWT_ACCESS_TOKEN_EXP_IN_SEC: Joi.number().required(),
    JWT_REFRESH_TOKEN_EXP_IN_SEC: Joi.number().required(),
    DEFAULT_ADMIN_USER_PASSWORD: Joi.string().required(),

    OTP_LENGTH: Joi.number().required(),
    OTP_TTL_SEC: Joi.number().required(),
  };

  constructor() {
    this.envConfig = this.validateInput(process.env);
    console.log(
      'AppConfigService -> constructor -> this.envConfig',
      this.envConfig,
    );
  }

  private validateInput(envConfig: dotenv.DotenvParseOutput): EnvConfig {
    const envVarsSchema: Joi.ObjectSchema = Joi.object(this.validationScheme);
    const validation = envVarsSchema.validate(envConfig, {
      abortEarly: false,
      allowUnknown: true,
    });
    if (validation.error) {
      throw new Error(
        `Config validation error:\n${map(
          get(validation, 'error.details'),
          (x) => x.message,
        ).join('\n')}`,
      );
    }

    // ignore unknown keys
    const validatedEnvConfig = validation.value as EnvConfig;
    return validatedEnvConfig;
  }

  get app(): AppConfig {
    return {
      env: String(this.envConfig.APP_ENV),
      port: this.envConfig.APP_PORT,
      host: String(this.envConfig.APP_HOST),
    };
  }

  get db(): DBConfig {
    return {
      host: String(this.envConfig.DB_HOST),
      port: this.envConfig.DB_PORT,
      name: String(this.envConfig.DB_NAME),
      user: String(this.envConfig.DB_USER),
      pass: String(this.envConfig.DB_PASS),
    };
  }

  get jwt(): JWTConfig {
    return {
      accessTokenExpInSec: this.envConfig.JWT_ACCESS_TOKEN_EXP_IN_SEC,
      refreshTokenExpInSec: this.envConfig.JWT_REFRESH_TOKEN_EXP_IN_SEC,
      publicKey: Buffer.from(
        this.envConfig.JWT_PUBLIC_KEY_BASE64,
        'base64',
      ).toString('utf-8'),
      privateKey: Buffer.from(
        this.envConfig.JWT_PRIVATE_KEY_BASE64,
        'base64',
      ).toString('utf-8'),
    };
  }

  get otp(): OTPConfig {
    return {
      length: this.envConfig.OTP_LENGTH,
      ttl: this.envConfig.OTP_TTL_SEC * 1000,
    };
  }

  get redis(): RedisConfig {
    return {
      host: String(this.envConfig.REDIS_HOST),
      port: this.envConfig.REDIS_PORT,
      pass: String(this.envConfig.REDIS_PASS),
    };
  }

  get defaultAdminUserPassword(): string {
    return String(this.envConfig.DEFAULT_ADMIN_USER_PASSWORD);
  }
}
