import { Injectable } from '@nestjs/common';
import { compare, hash } from 'bcrypt';
import { plainToInstance } from 'class-transformer';
import { QueryRunner } from 'typeorm';

import {
  AppExceptionCode,
  getAppException,
} from '../../shared/exceptions/app.exception';
import { AppLogger } from '../../shared/logger/logger.service';
import { RequestContext } from '../../shared/request-context/request-context.dto';
import { CreateUserInput } from '../dtos/user-create.dto';
import { UserOutput } from '../dtos/user-output.dto';
import {
  BackofficeUpdateUserInput,
  UpdateUserInput,
} from '../dtos/user-update.dto';
import { User, UserStatus } from '../entities/user.entity';
import { UserRepository } from '../repositories/user.repository';

@Injectable()
export class UserService {
  constructor(
    private repository: UserRepository,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(UserService.name);
  }

  async createUser(
    ctx: RequestContext,
    input: CreateUserInput,
    queryRunner?: QueryRunner,
  ): Promise<UserOutput> {
    this.logger.log(ctx, `${this.createUser.name} was called`);

    const existingUser = await this.repository.findOne({
      where: { email: input.email },
    });

    if (existingUser) {
      throw getAppException(AppExceptionCode.USER_EMAIL_ALREADY_EXISTS);
    }

    const user = plainToInstance(User, input);

    user.password = await hash(input.password, 10);

    this.logger.log(ctx, `calling ${UserRepository.name}.saveUser`);
    await this.repository
      .createQueryBuilder('user', queryRunner)
      .insert()
      .values(user)
      .execute();

    return plainToInstance(UserOutput, user, {
      excludeExtraneousValues: true,
    });
  }

  async validateEmailPassword(
    ctx: RequestContext,
    email: string,
    pass: string,
  ): Promise<UserOutput> {
    this.logger.log(ctx, `${this.validateEmailPassword.name} was called`);

    this.logger.log(ctx, `calling ${UserRepository.name}.findOne`);
    const user = await this.repository.findOne({ where: { email } });
    if (!user) throw getAppException(AppExceptionCode.USER_NOT_FOUND);

    const match = await compare(pass, user.password);
    if (!match) throw getAppException(AppExceptionCode.USER_PASSWORD_INCORRECT);

    return plainToInstance(UserOutput, user, {
      excludeExtraneousValues: true,
    });
  }

  async getUsers(
    ctx: RequestContext,
    limit: number,
    offset: number,
    queryRunner?: QueryRunner,
  ): Promise<{ users: UserOutput[]; count: number }> {
    this.logger.log(ctx, `${this.getUsers.name} was called`);

    this.logger.log(ctx, `calling ${UserRepository.name}.findAndCount`);
    const [users, count] = await this.repository
      .createQueryBuilder('user', queryRunner)
      .getManyAndCount();

    const usersOutput = plainToInstance(UserOutput, users, {
      excludeExtraneousValues: true,
    });

    return { users: usersOutput, count };
  }

  async findById(ctx: RequestContext, id: number): Promise<UserOutput> {
    this.logger.log(ctx, `${this.findById.name} was called`);

    this.logger.log(ctx, `calling ${UserRepository.name}.findOne`);
    const user = await this.repository
      .createQueryBuilder('user')
      .where('user.id = :id', { id })
      .getOne();
    return plainToInstance(UserOutput, user, {
      excludeExtraneousValues: true,
    });
  }

  async getUserById(
    ctx: RequestContext,
    id: number,
    queryRunner?: QueryRunner,
  ): Promise<UserOutput> {
    this.logger.log(ctx, `${this.getUserById.name} was called`);

    this.logger.log(ctx, `calling ${UserRepository.name}.getById`);
    const user = await this.repository.getById(id, queryRunner);

    return plainToInstance(UserOutput, user, {
      excludeExtraneousValues: true,
    });
  }

  async findByEmail(
    ctx: RequestContext,
    email: string,
    queryRunner?: QueryRunner,
  ): Promise<UserOutput> {
    this.logger.log(ctx, `${this.findByEmail.name} was called`);

    this.logger.log(ctx, `calling ${UserRepository.name}.findOne`);
    const user = await this.repository
      .createQueryBuilder('user', queryRunner)
      .where('user.email = :email', { email })
      .getOne();

    return plainToInstance(UserOutput, user, {
      excludeExtraneousValues: true,
    });
  }

  async updateUser(
    ctx: RequestContext,
    userId: number,
    input: UpdateUserInput | BackofficeUpdateUserInput,
    queryRunner?: QueryRunner,
  ): Promise<UserOutput> {
    this.logger.log(ctx, `${this.updateUser.name} was called`);

    this.logger.log(ctx, `calling ${UserRepository.name}.getById`);
    const user = await this.repository.getById(userId);

    if (input.email) {
      const emailUser = await this.repository.findOne({
        where: { email: input.email },
      });
      if (emailUser && emailUser.id !== userId) {
        throw getAppException(AppExceptionCode.USER_EMAIL_ALREADY_EXISTS);
      }
      user.email = input.email;
    }
    // Hash the password if it exists in the input payload.
    if (input.password) {
      input.password = await hash(input.password, 10);
    }

    // merges the input (2nd line) to the found user (1st line)
    const updatedUser: User = {
      ...user,
      ...plainToInstance(User, input),
    };

    this.logger.log(ctx, `calling ${UserRepository.name}.save`);
    await this.repository
      .createQueryBuilder('user', queryRunner)
      .update()
      .set(updatedUser)
      .where('id = :id', { id: userId })
      .execute();

    return plainToInstance(UserOutput, updatedUser, {
      excludeExtraneousValues: true,
    });
  }

  async updateStatus(
    ctx: RequestContext,
    userId: number,
    status: UserStatus,
    queryRunner?: QueryRunner,
  ): Promise<UserOutput> {
    this.logger.log(ctx, `${this.updateStatus.name} was called`);

    this.logger.log(ctx, `calling ${UserRepository.name}.getById`);
    const user = await this.repository.getById(userId, queryRunner);

    user.status = status;

    this.logger.log(ctx, `calling ${UserRepository.name}.save`);
    await this.repository
      .createQueryBuilder('user', queryRunner)
      .update()
      .set(user)
      .where('id = :id', { id: userId })
      .execute();
    return plainToInstance(UserOutput, user, {
      excludeExtraneousValues: true,
    });
  }

  async updatePassword(
    ctx: RequestContext,
    userId: number,
    password: string,
    queryRunner?: QueryRunner,
  ): Promise<void> {
    this.logger.log(ctx, `${this.updatePassword.name} was called`);

    this.logger.log(ctx, `calling ${UserRepository.name}.getById`);
    const user = await this.repository.getById(userId, queryRunner);

    user.password = await hash(password, 10);

    this.logger.log(ctx, `calling ${UserRepository.name}.save`);

    await this.repository
      .createQueryBuilder('user', queryRunner)
      .update()
      .set(user)
      .where('id = :id', { id: userId })
      .execute();
  }
}
