import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { STRATEGY_USER_LOCAL } from '../constants/strategy.constant';

@Injectable()
export class LocalUserAuthGuard extends AuthGuard(STRATEGY_USER_LOCAL) {}
