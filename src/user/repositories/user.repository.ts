import { Injectable, NotFoundException } from '@nestjs/common';
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
      throw new NotFoundException('User not found');
    }

    return user;
  }
}
