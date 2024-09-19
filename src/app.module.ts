import { Module } from '@nestjs/common';
import { OperatorModule } from 'src/operator/operator.module';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { SharedModule } from './shared/shared.module';
import { UserModule } from './user/user.module';

@Module({
  imports: [SharedModule, AuthModule, UserModule, OperatorModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
