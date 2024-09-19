import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { STRATEGY_OPERATOR_LOCAL } from '../constants/strategy.constant';

@Injectable()
export class LocalOperatorAuthGuard extends AuthGuard(
  STRATEGY_OPERATOR_LOCAL,
) {}
