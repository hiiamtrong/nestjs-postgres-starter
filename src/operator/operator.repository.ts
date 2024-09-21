import { Injectable } from '@nestjs/common';
import { Operator } from 'src/operator/entities/operator.entity';
import {
  AppExceptionCode,
  getAppException,
} from 'src/shared/exceptions/app.exception';
import { DataSource, Repository } from 'typeorm';

@Injectable()
export class OperatorRepository extends Repository<Operator> {
  constructor(private dataSource: DataSource) {
    super(Operator, dataSource.createEntityManager());
  }

  async getById(id: number): Promise<Operator> {
    const operator = await this.findOne({ where: { id } });
    if (!operator) {
      throw getAppException(AppExceptionCode.OPERATOR_NOT_FOUND);
    }

    return operator;
  }
}
