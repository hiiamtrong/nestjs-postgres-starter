import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  AppExceptionCode,
  getAppException,
} from 'src/shared/exceptions/app.exception';

import { ROLE } from '../constants/role.constant';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredPermissions = this.reflector.getAllAndOverride<ROLE[]>(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredPermissions) {
      return true;
    }
    const { user } = context.switchToHttp().getRequest();

    if (
      requiredPermissions.some(
        (permission) => user.permissions?.has(permission),
      )
    ) {
      return true;
    }

    throw getAppException(AppExceptionCode.OPERATOR_NOT_AUTHORIZED);
  }
}
