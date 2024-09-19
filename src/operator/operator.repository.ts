import { Injectable, NotFoundException } from '@nestjs/common';
import { Operator } from 'src/operator/entities/operator.entity';
import { DataSource, Repository } from 'typeorm';

@Injectable()
export class OperatorRepository extends Repository<Operator> {
  constructor(private dataSource: DataSource) {
    super(Operator, dataSource.createEntityManager());
  }

  async getById(id: number): Promise<Operator> {
    const operator = await this.findOne({ where: { id } });
    if (!operator) {
      throw new NotFoundException();
    }

    return operator;
  }
}
