import { ROLE } from './../../auth/constants/role.constant';

/**
 * The actor who is perfoming the action
 */
export enum ActorType {
  USER,
  OPERATOR,
}
export interface Actor {
  id: number;
  type: string;
  roles: ROLE[];
}
