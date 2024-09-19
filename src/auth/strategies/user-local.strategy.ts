import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { Strategy } from 'passport-local';

import { AppLogger } from '../../shared/logger/logger.service';
import { createRequestContext } from '../../shared/request-context/util';
import { STRATEGY_USER_LOCAL } from '../constants/strategy.constant';
import { UserAccessTokenClaims } from '../dtos/user-auth-token.dto';
import { UserAuthService } from '../services/user-auth.service';

@Injectable()
export class UserLocalStrategy extends PassportStrategy(
  Strategy,
  STRATEGY_USER_LOCAL,
) {
  constructor(
    private authService: UserAuthService,
    private readonly logger: AppLogger,
  ) {
    // Add option passReqToCallback: true to configure strategy to be request-scoped.
    super({
      usernameField: 'phone',
      passwordField: 'password',
      passReqToCallback: true,
    });
    this.logger.setContext(UserLocalStrategy.name);
  }

  async validate(
    request: Request,
    phone: string,
    password: string,
  ): Promise<UserAccessTokenClaims> {
    const ctx = createRequestContext(request);

    this.logger.log(ctx, `${this.validate.name} was called`);

    const user = await this.authService.validateUser(ctx, phone, password);
    return user;
  }
}
