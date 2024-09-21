import {
  Injectable
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { plainToInstance } from 'class-transformer';
import { UserResetPasswordInput } from 'src/auth/dtos/user-auth-reset-password.dto';
import { UserAuthVerityOtpOutput } from 'src/auth/dtos/user-auth-verity-otp.dto';
import { OtpService } from 'src/auth/services/otp.service';
import { AppConfigService } from 'src/shared/configs/config.service';
import { TransactionalConnection } from 'src/shared/transactional/transactional';
import { UserStatus } from 'src/user/entities/user.entity';

import {
  AppExceptionCode,
  getAppException,
} from '../../shared/exceptions/app.exception';
import { AppLogger } from '../../shared/logger/logger.service';
import { RequestContext } from '../../shared/request-context/request-context.dto';
import { UserOutput } from '../../user/dtos/user-output.dto';
import { UserService } from '../../user/services/user.service';
import {
  UserRegisterInput,
  UserRegisterOutput,
} from '../dtos/user-auth-register.dto';
import {
  UserAccessTokenClaims,
  UserAuthTokenOutput,
} from '../dtos/user-auth-token.dto';

@Injectable()
export class UserAuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private config: AppConfigService,
    private readonly logger: AppLogger,
    private readonly transactionConnection: TransactionalConnection,
    private readonly otpService: OtpService,
  ) {
    this.logger.setContext(UserAuthService.name);
  }

  async validateUser(
    ctx: RequestContext,
    email: string,
    pass: string,
  ): Promise<UserAccessTokenClaims> {
    this.logger.log(ctx, `${this.validateUser.name} was called`);

    const user = await this.userService.validateEmailPassword(ctx, email, pass);

    if (user.status !== UserStatus.ACTIVE) {
      throw getAppException(AppExceptionCode.USER_NOT_ACTIVE);
    }

    return user;
  }

  login(ctx: RequestContext): UserAuthTokenOutput {
    this.logger.log(ctx, `${this.login.name} was called`);

    return this.getAuthToken(ctx, ctx.user);
  }

  async register(
    ctx: RequestContext,
    input: UserRegisterInput,
  ): Promise<UserRegisterOutput> {
    this.logger.log(ctx, `${this.register.name} was called`);
    const queryRunner = await this.transactionConnection.create();
    try {
      const registeredUser = await this.userService.createUser(
        ctx,
        input,
        queryRunner,
      );

      // Generate OTP
      await this.otpService.sendEmailOtp(registeredUser.email);

      await queryRunner.commitTransaction();

      return plainToInstance(UserRegisterOutput, registeredUser, {
        excludeExtraneousValues: true,
      });
    } catch (error) {
      if (queryRunner?.isTransactionActive) {
        await queryRunner.rollbackTransaction();
      }
      throw error;
    }
  }

  async verifyOtp(
    ctx: RequestContext,
    email: string,
    otp: string,
  ): Promise<UserAuthVerityOtpOutput> {
    this.logger.log(ctx, `${this.verifyOtp.name} was called`);

    let user = await this.userService.findByEmail(ctx, email);
    if (!user) {
      throw getAppException(AppExceptionCode.USER_NOT_FOUND);
    }

    if (user.status === UserStatus.ACTIVE) {
      throw getAppException(AppExceptionCode.USER_ALREADY_ACTIVE);
    }

    const isOtpValid = await this.otpService.verifyEmailOtp(email, otp);
    if (!isOtpValid) {
      throw getAppException(AppExceptionCode.USER_OTP_INCORRECT);
    }

    // Update user status to active
    user = await this.userService.updateStatus(ctx, user.id, UserStatus.ACTIVE);

    // Delete the OTP from cache
    await this.otpService.clearEmailOtp(email);

    return plainToInstance(UserAuthVerityOtpOutput, user, {
      excludeExtraneousValues: true,
    });
  }

  async resendOtp(ctx: RequestContext, email: string): Promise<void> {
    this.logger.log(ctx, `${this.resendOtp.name} was called`);

    const user = await this.userService.findByEmail(ctx, email);
    if (!user) {
      throw getAppException(AppExceptionCode.USER_NOT_FOUND);
    }

    if (user.status === UserStatus.ACTIVE) {
      throw getAppException(AppExceptionCode.USER_ALREADY_ACTIVE);
    }

    await this.otpService.sendEmailOtp(email);
  }

  async refreshToken(ctx: RequestContext): Promise<UserAuthTokenOutput> {
    this.logger.log(ctx, `${this.refreshToken.name} was called`);

    const user = await this.userService.findById(ctx, ctx.user.id);
    if (!user) {
      throw getAppException(AppExceptionCode.USER_NOT_FOUND);
    }

    return this.getAuthToken(ctx, user);
  }

  async forgotPassword(ctx: RequestContext, email: string): Promise<void> {
    this.logger.log(ctx, `${this.forgotPassword.name} was called`);

    const user = await this.userService.findByEmail(ctx, email);
    if (!user) {
      throw getAppException(AppExceptionCode.USER_NOT_FOUND);
    }

    await this.otpService.sendEmailOtp(email);
  }

  async resetPassword(
    ctx: RequestContext,
    input: UserResetPasswordInput,
  ): Promise<void> {
    this.logger.log(ctx, `${this.resetPassword.name} was called`);

    const user = await this.userService.findByEmail(ctx, input.email);
    if (!user) {
      throw getAppException(AppExceptionCode.USER_NOT_FOUND);
    }

    const isOtpValid = await this.otpService.verifyEmailOtp(
      input.email,
      input.otp,
    );
    if (!isOtpValid) {
      throw getAppException(AppExceptionCode.USER_OTP_INCORRECT);
    }

    await this.userService.updatePassword(ctx, user.id, input.password);
    await this.otpService.clearEmailOtp(input.email);
  }

  getAuthToken(
    ctx: RequestContext,
    user: UserAccessTokenClaims | UserOutput,
  ): UserAuthTokenOutput {
    this.logger.log(ctx, `${this.getAuthToken.name} was called`);

    const subject = { sub: user.id };
    const payload = {
      email: user.email,
      sub: user.id,
    };

    const authToken = {
      refreshToken: this.jwtService.sign(subject, {
        expiresIn: this.config.jwt.refreshTokenExpInSec,
      }),
      accessToken: this.jwtService.sign(
        { ...payload, ...subject },
        { expiresIn: this.config.jwt.accessTokenExpInSec },
      ),
    };
    return plainToInstance(UserAuthTokenOutput, authToken, {
      excludeExtraneousValues: true,
    });
  }
}
