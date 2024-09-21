import { Injectable, NotFoundException } from '@nestjs/common';
import { AppExceptionCode, getAppException } from 'src/shared/exceptions/app.exception';
import { DataSource, QueryRunner, Repository } from 'typeorm';

import { User } from '../entities/user.entity';

@Injectable()
export class UserRepository extends Repository<User> {
  constructor(private dataSource: DataSource) {
    super(User, dataSource.createEntityManager());
  }

  async getById(id: number, queryRunner?: QueryRunner): Promise<User> {
    const user = await this.createQueryBuilder('user', queryRunner)
      .where('user.id = :id', {
        id,
      })
      .getOne();

    if (!user) {
      throw getAppException(AppExceptionCode.USER_NOT_FOUND);
    }

    return user;
  }
}
