import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BackOfficeUserController } from 'src/user/controllers/backoffice-user.controller';

import { JwtUserAuthStrategy } from '../auth/strategies/jwt-user-auth.strategy';
import { UserController } from './controllers/user.controller';
import { User } from './entities/user.entity';
import { UserRepository } from './repositories/user.repository';
import { UserService } from './services/user.service';
import { UserAclService } from './services/user-acl.service';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [UserService, JwtUserAuthStrategy, UserAclService, UserRepository],
  controllers: [UserController, BackOfficeUserController],
  exports: [UserService],
})
export class UserModule {}
