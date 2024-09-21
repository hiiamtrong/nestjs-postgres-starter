import { CacheModule, CacheOptions } from '@nestjs/cache-manager';
import { Global, Module } from '@nestjs/common';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { redisStore } from 'cache-manager-ioredis-yet';
import type { RedisClientOptions } from 'redis';
import {
  STRATEGY_JWT_OPERATOR_AUTH,
  STRATEGY_JWT_USER_AUTH,
} from 'src/auth/constants/strategy.constant';
import { AppConfigModule } from 'src/shared/configs/config.module';
import { AppConfigService } from 'src/shared/configs/config.service';
import { BaseApiResponseInterceptor } from 'src/shared/filters/all-responses.filter';
import { TransactionalConnection } from 'src/shared/transactional/transactional';

import { AllExceptionsFilter } from './filters/all-exceptions.filter';
import { LoggingInterceptor } from './interceptors/logging.interceptor';
import { AppLoggerModule } from './logger/logger.module';

@Global()
@Module({
  imports: [
    AppConfigModule,
    PassportModule.register({ defaultStrategy: STRATEGY_JWT_USER_AUTH }),
    PassportModule.register({ defaultStrategy: STRATEGY_JWT_OPERATOR_AUTH }),
    CacheModule.registerAsync<RedisClientOptions>({
      imports: [AppConfigModule],
      inject: [AppConfigService],
      useFactory: async (config: AppConfigService): Promise<CacheOptions> => {
        const store = await redisStore({
          host: config.redis.host,
          port: config.redis.port,
          password: config.redis.pass,
        });
        return {
          store,
        };
      },
    }),
    TypeOrmModule.forRootAsync({
      imports: [AppConfigModule],
      inject: [AppConfigService],
      useFactory: async (config: AppConfigService) => ({
        type: 'postgres',
        host: config.db.host,
        port: config.db.port,
        database: config.db.name,
        username: config.db.user,
        password: config.db.pass,
        entities: [__dirname + '/../**/entities/*.entity{.ts,.js}'],
        // Timezone configured on the Postgres server.
        // This is used to typecast server date/time values to JavaScript Date object and vice versa.
        timezone: 'Z',
        synchronize: false,
        debug: config.app.env === 'development',
      }),
    }),
    AppLoggerModule,
  ],
  exports: [
    AppLoggerModule,
    AppConfigModule,
    TransactionalConnection,
    CacheModule,
  ],
  providers: [
    { provide: APP_INTERCEPTOR, useClass: LoggingInterceptor },
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: BaseApiResponseInterceptor,
    },
    TransactionalConnection,
  ],
})
export class SharedModule {}
