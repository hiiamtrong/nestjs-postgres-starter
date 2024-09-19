import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { Strategy } from 'passport-local';
import { OperatorAccessTokenClaims } from 'src/auth/dtos/operator-auth-token.dto';
import { OperatorAuthService } from 'src/auth/services/operator-auth.service';

import { AppLogger } from '../../shared/logger/logger.service';
import { createRequestContext } from '../../shared/request-context/util';
import { STRATEGY_OPERATOR_LOCAL } from '../constants/strategy.constant';

@Injectable()
export class OperatorLocalStrategy extends PassportStrategy(
  Strategy,
  STRATEGY_OPERATOR_LOCAL,
) {
  constructor(
    private authOperatorService: OperatorAuthService,
    private readonly logger: AppLogger,
  ) {
    // Add option passReqToCallback: true to configure strategy to be request-scoped.
    super({
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true,
    });
    this.logger.setContext(OperatorLocalStrategy.name);
  }

  async validate(
    request: Request,
    email: string,
    password: string,
  ): Promise<OperatorAccessTokenClaims> {
    const ctx = createRequestContext(request);

    this.logger.log(ctx, `${this.validate.name} was called`);

    const operator = await this.authOperatorService.validateOperator(
      ctx,
      email,
      password,
    );
    return operator;
  }
}
