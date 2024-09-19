import { ROLE } from 'src/auth/constants/role.constant';

export const STRATEGY_USER_LOCAL = 'user-local';
export const STRATEGY_JWT_USER_AUTH = 'jwt-user-auth';
export const STRATEGY_JWT_USER_REFRESH = 'jwt-user-refresh';

export const STRATEGY_OPERATOR_LOCAL = 'operator-local';
export const STRATEGY_JWT_OPERATOR_AUTH = 'jwt-operator-auth';
export const STRATEGY_JWT_OPERATOR_REFRESH = 'jwt-operator-refresh';

export class AuthStrategyValidationOutput {
  id: number;
  username: string;
  phone: string;
  email: string;
  role: ROLE;
  permissions: Set<string>;
}
