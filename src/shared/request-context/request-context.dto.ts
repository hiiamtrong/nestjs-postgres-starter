import { AuthStrategyValidationOutput } from 'src/auth/constants/strategy.constant';

export class RequestContext {
  public requestID: string;

  public url: string;

  public ip: string;

  public user: AuthStrategyValidationOutput;
}
