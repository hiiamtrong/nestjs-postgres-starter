import { Injectable } from '@nestjs/common';
import { compare, hash } from 'bcrypt';
import { plainToInstance } from 'class-transformer';
import { OperatorOutput } from 'src/operator/dtos/operator.dto';
import { OperatorStatus } from 'src/operator/entities/operator.entity';
import { OperatorRepository } from 'src/operator/operator.repository';
import {
  AppExceptionCode,
  getAppException,
} from 'src/shared/exceptions/app.exception';
import { AppLogger } from 'src/shared/logger/logger.service';
import { RequestContext } from 'src/shared/request-context/request-context.dto';

@Injectable()
export class OperatorService {
  constructor(
    private readonly repository: OperatorRepository,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(OperatorService.name);
  }

  async validateEmailPassword(
    ctx: RequestContext,
    email: string,
    pass: string,
  ): Promise<OperatorOutput> {
    this.logger.log(ctx, `${this.validateEmailPassword.name} was called`);

    this.logger.log(ctx, `calling ${OperatorRepository.name}.findOne`);
    const operator = await this.repository.findOne({ where: { email } });
    if (!operator) throw getAppException(AppExceptionCode.OPERATOR_NOT_FOUND);

    const match = await compare(pass, operator.password);
    if (!match) throw getAppException(AppExceptionCode.OPERATOR_PASSWORD_INCORRECT);

    return plainToInstance(OperatorOutput, operator, {
      excludeExtraneousValues: true,
    });
  }

  async findById(ctx: RequestContext, id: number) {
    this.logger.log(ctx, `${this.findById.name} was called`);

    this.logger.log(ctx, `calling ${OperatorRepository.name}.getById`);
    const operator = await this.repository.findOneBy({ id });
    if (!operator) throw getAppException(AppExceptionCode.OPERATOR_NOT_FOUND);
    return plainToInstance(OperatorOutput, operator, {
      excludeExtraneousValues: true,
    });
  }

  async findByEmail(ctx: RequestContext, email: string) {
    this.logger.log(ctx, `${this.findByEmail.name} was called`);

    this.logger.log(ctx, `calling ${OperatorRepository.name}.findOne`);
    const operator = await this.repository.findOne({ where: { email } });
    if (!operator) throw getAppException(AppExceptionCode.OPERATOR_NOT_FOUND);
    return plainToInstance(OperatorOutput, operator, {
      excludeExtraneousValues: true,
    });
  }

  async updateStatus(ctx: RequestContext, id: number, status: OperatorStatus) {
    this.logger.log(ctx, `${this.updateStatus.name} was called`);

    this.logger.log(ctx, `calling ${OperatorRepository.name}.getById`);
    const operator = await this.repository.getById(id);
    if (!operator) throw getAppException(AppExceptionCode.OPERATOR_NOT_FOUND);

    operator.status = status;

    this.logger.log(ctx, `calling ${OperatorRepository.name}.save`);
    await this.repository.save(operator);
    return plainToInstance(OperatorOutput, operator, {
      excludeExtraneousValues: true,
    });
  }

  async updatePassword(
    ctx: RequestContext,
    id: number,
    password: string,
  ): Promise<void> {
    this.logger.log(ctx, `${this.updatePassword.name} was called`);

    this.logger.log(ctx, `calling ${OperatorRepository.name}.getById`);
    const operator = await this.repository.getById(id);
    if (!operator) throw getAppException(AppExceptionCode.OPERATOR_NOT_FOUND);

    operator.password = await this.hashPassword(password);

    this.logger.log(ctx, `calling ${OperatorRepository.name}.save`);
    await this.repository.save(operator);
  }

  generateRandomPassword() {
    return Math.random().toString(36).slice(-8);
  }

  hashPassword(password: string) {
    return hash(password, 10);
  }
}
