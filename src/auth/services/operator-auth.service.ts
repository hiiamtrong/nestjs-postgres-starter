import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { plainToInstance } from 'class-transformer';
import { OperatorResetPasswordInput } from 'src/auth/dtos/operator-auth-reset-password.dto';
import {
  OperatorAccessTokenClaims,
  OperatorAuthTokenOutput,
} from 'src/auth/dtos/operator-auth-token.dto';
import { OperatorAuthVerityOtpOutput } from 'src/auth/dtos/operator-auth-verity-otp.dto';
import { OtpService } from 'src/auth/services/otp.service';
import { OperatorOutput } from 'src/operator/dtos/operator.dto';
import { OperatorStatus } from 'src/operator/entities/operator.entity';
import { OperatorService } from 'src/operator/operator.service';
import { AppConfigService } from 'src/shared/configs/config.service';
import { TransactionalConnection } from 'src/shared/transactional/transactional';

import { AppLogger } from '../../shared/logger/logger.service';
import { RequestContext } from '../../shared/request-context/request-context.dto';

@Injectable()
export class OperatorAuthService {
  constructor(
    private operatorService: OperatorService,
    private jwtService: JwtService,
    private config: AppConfigService,
    private readonly logger: AppLogger,
    private readonly transactionConnection: TransactionalConnection,
    private readonly otpService: OtpService,
  ) {
    this.logger.setContext(OperatorAuthService.name);
  }

  async validateOperator(
    ctx: RequestContext,
    email: string,
    pass: string,
  ): Promise<OperatorAccessTokenClaims> {
    this.logger.log(ctx, `${this.validateOperator.name} was called`);

    const operator = await this.operatorService.validateEmailPassword(
      ctx,
      email,
      pass,
    );

    // Prevent disabled users from logging in.
    if (operator.status !== OperatorStatus.ACTIVE) {
      throw new ForbiddenException(
        'This operator account has been disabled or deleted',
      );
    }

    return operator;
  }

  login(ctx: RequestContext): OperatorAuthTokenOutput {
    this.logger.log(ctx, `${this.login.name} was called`);

    return this.getAuthToken(ctx, ctx.user);
  }

  async verifyOtp(
    ctx: RequestContext,
    email: string,
    otp: string,
  ): Promise<OperatorAuthVerityOtpOutput> {
    this.logger.log(ctx, `${this.verifyOtp.name} was called`);

    let operator = await this.operatorService.findByEmail(ctx, email);
    if (!operator) {
      throw new BadRequestException('Invalid email number');
    }

    if (operator.status === OperatorStatus.ACTIVE) {
      throw new BadRequestException('Operator is already active');
    }

    const isOtpValid = await this.otpService.verifyPhoneOtp(email, otp);
    if (!isOtpValid) {
      throw new BadRequestException('Invalid OTP');
    }

    // Update user status to active
    operator = await this.operatorService.updateStatus(
      ctx,
      operator.id,
      OperatorStatus.ACTIVE,
    );

    // Delete the OTP from cache
    await this.otpService.clearEmailOtp(email);

    return plainToInstance(OperatorAuthVerityOtpOutput, operator, {
      excludeExtraneousValues: true,
    });
  }

  async resendOtp(ctx: RequestContext, email: string): Promise<void> {
    this.logger.log(ctx, `${this.resendOtp.name} was called`);

    const operator = await this.operatorService.findByEmail(ctx, email);
    if (!operator) {
      throw new BadRequestException('Invalid email number');
    }

    if (operator.status === OperatorStatus.ACTIVE) {
      throw new BadRequestException('Operator is already active');
    }

    await this.otpService.sendEmailOtp(email);
  }

  async refreshToken(ctx: RequestContext): Promise<OperatorAuthTokenOutput> {
    this.logger.log(ctx, `${this.refreshToken.name} was called`);

    const user = await this.operatorService.findById(ctx, ctx.user.id);
    if (!user) {
      throw new BadRequestException('Invalid user id');
    }

    return this.getAuthToken(ctx, user);
  }

  async forgotPassword(ctx: RequestContext, email: string): Promise<void> {
    this.logger.log(ctx, `${this.forgotPassword.name} was called`);

    const operator = await this.operatorService.findByEmail(ctx, email);
    if (!operator) {
      throw new BadRequestException('Invalid email number');
    }

    await this.otpService.sendEmailOtp(email);
  }

  async resetPassword(
    ctx: RequestContext,
    input: OperatorResetPasswordInput,
  ): Promise<void> {
    this.logger.log(ctx, `${this.resetPassword.name} was called`);

    const operator = await this.operatorService.findByEmail(ctx, input.email);
    if (!operator) {
      throw new BadRequestException('Invalid phone number');
    }

    const isOtpValid = await this.otpService.verifyEmailOtp(
      input.email,
      input.otp,
    );
    if (!isOtpValid) {
      throw new BadRequestException('Invalid OTP');
    }

    await this.operatorService.updatePassword(ctx, operator.id, input.password);
    await this.otpService.clearEmailOtp(input.email);
  }

  getAuthToken(
    ctx: RequestContext,
    operator: OperatorAccessTokenClaims | OperatorOutput,
  ): OperatorAuthTokenOutput {
    this.logger.log(ctx, `${this.getAuthToken.name} was called`);

    const subject = { sub: operator.id };
    const payload = {
      email: operator.email,
      sub: operator.id,
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
    return plainToInstance(OperatorAuthTokenOutput, authToken, {
      excludeExtraneousValues: true,
    });
  }
}
