import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { UserForgotPasswordInput } from 'src/auth/dtos/user-auth-forgot-password.dto';
import { UserRefreshTokenInput } from 'src/auth/dtos/user-auth-refresh-token.dto';
import { UserAuthResendOtpInput } from 'src/auth/dtos/user-auth-resend-otp.dto';
import { UserResetPasswordInput } from 'src/auth/dtos/user-auth-reset-password.dto';
import {
  UserAuthVerityOtpInput,
  UserAuthVerityOtpOutput,
} from 'src/auth/dtos/user-auth-verity-otp.dto';

import {
  BaseApiErrorResponse,
  BaseApiResponse,
  SwaggerBaseApiResponse,
} from '../../shared/dtos/base-api-response.dto';
import { AppLogger } from '../../shared/logger/logger.service';
import { ReqContext } from '../../shared/request-context/req-context.decorator';
import { RequestContext } from '../../shared/request-context/request-context.dto';
import { UserLoginInput } from '../dtos/user-auth-login.dto';
import {
  UserRegisterInput,
  UserRegisterOutput,
} from '../dtos/user-auth-register.dto';
import { UserAuthTokenOutput } from '../dtos/user-auth-token.dto';
import { JwtUserRefreshGuard } from '../guards/jwt-refresh.guard';
import { LocalUserAuthGuard } from '../guards/local-auth.guard';
import { UserAuthService } from '../services/user-auth.service';

@ApiTags('User Auth')
@Controller('auth')
export class UserAuthController {
  constructor(
    private readonly authService: UserAuthService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(UserAuthController.name);
  }
  @Post('login')
  @ApiOperation({
    summary: 'User login API',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    type: SwaggerBaseApiResponse(UserAuthTokenOutput),
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    type: BaseApiErrorResponse,
  })
  @HttpCode(HttpStatus.OK)
  @UseGuards(LocalUserAuthGuard)
  @UseInterceptors(ClassSerializerInterceptor)
  login(
    @ReqContext() ctx: RequestContext,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    @Body() credential: UserLoginInput,
  ): BaseApiResponse<UserAuthTokenOutput> {
    this.logger.log(ctx, `${this.login.name} was called`);

    const authToken = this.authService.login(ctx);
    return { data: authToken, meta: {} };
  }

  @Post('register')
  @ApiOperation({
    summary: 'User registration API',
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    type: SwaggerBaseApiResponse(UserRegisterOutput),
  })
  async registerLocal(
    @ReqContext() ctx: RequestContext,
    @Body() input: UserRegisterInput,
  ): Promise<BaseApiResponse<UserRegisterOutput>> {
    const registeredUser = await this.authService.register(ctx, input);
    return { data: registeredUser, meta: {} };
  }

  @Post('verify-otp')
  @ApiOperation({
    summary: 'Verify OTP API',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    type: SwaggerBaseApiResponse(UserAuthVerityOtpOutput),
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    type: BaseApiErrorResponse,
  })
  async verifyOtp(
    @ReqContext() ctx: RequestContext,
    @Body() input: UserAuthVerityOtpInput,
  ): Promise<BaseApiResponse<UserAuthVerityOtpOutput>> {
    const res = await this.authService.verifyOtp(ctx, input.phone, input.otp);
    return { data: res, meta: {} };
  }

  @Post('resend-otp')
  @ApiOperation({
    summary: 'Resend OTP API',
  })
  @ApiResponse({
    status: HttpStatus.NO_CONTENT,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    type: BaseApiErrorResponse,
  })
  @HttpCode(HttpStatus.NO_CONTENT)
  async resendOtp(
    @ReqContext() ctx: RequestContext,
    @Body() input: UserAuthResendOtpInput,
  ): Promise<BaseApiResponse<void>> {
    await this.authService.resendOtp(ctx, input.phone);
    return { data: null, meta: {} };
  }

  @Post('forgot-password')
  @ApiOperation({
    summary: 'Forgot password API',
  })
  @ApiResponse({
    status: HttpStatus.NO_CONTENT,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    type: BaseApiErrorResponse,
  })
  @HttpCode(HttpStatus.NO_CONTENT)
  async forgotPassword(
    @ReqContext() ctx: RequestContext,
    @Body() input: UserForgotPasswordInput,
  ): Promise<BaseApiResponse<void>> {
    await this.authService.forgotPassword(ctx, input.phone);
    return { data: null, meta: {} };
  }

  @Post('reset-password')
  @ApiOperation({
    summary: 'Reset password API',
  })
  @ApiResponse({
    status: HttpStatus.NO_CONTENT,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    type: BaseApiErrorResponse,
  })
  @HttpCode(HttpStatus.NO_CONTENT)
  async resetPassword(
    @ReqContext() ctx: RequestContext,
    @Body() input: UserResetPasswordInput,
  ): Promise<BaseApiResponse<void>> {
    await this.authService.resetPassword(ctx, input);
    return { data: null, meta: {} };
  }

  @Post('refresh-token')
  @ApiOperation({
    summary: 'Refresh access token API',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    type: SwaggerBaseApiResponse(UserAuthTokenOutput),
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    type: BaseApiErrorResponse,
  })
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtUserRefreshGuard)
  @UseInterceptors(ClassSerializerInterceptor)
  async refreshToken(
    @ReqContext() ctx: RequestContext,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    @Body() credential: UserRefreshTokenInput,
  ): Promise<BaseApiResponse<UserAuthTokenOutput>> {
    this.logger.log(ctx, `${this.refreshToken.name} was called`);

    const authToken = await this.authService.refreshToken(ctx);
    return { data: authToken, meta: {} };
  }
}
