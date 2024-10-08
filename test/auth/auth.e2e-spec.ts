import { HttpStatus, INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';

import { ROLE } from '../../src/auth/constants/role.constant';
import { UserLoginInput } from '../../src/auth/dtos/user-auth-login.dto';
import { RefreshTokenInput } from '../../src/auth/dtos/user-auth-refresh-token.dto';
import { UserRegisterInput } from '../../src/auth/dtos/user-auth-register.dto';
import { UserAuthTokenOutput } from '../../src/auth/dtos/user-auth-token.dto';
import { AppModule } from './../../src/app.module';
import {
  closeDBAfterTest,
  createDBEntities,
  resetDBBeforeTest,
  seedAdminUser,
} from './../test-utils';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let authTokenForAdmin: UserAuthTokenOutput;

  beforeAll(async () => {
    await resetDBBeforeTest();
    await createDBEntities();

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());
    await app.init();

    ({ authTokenForAdmin } = await seedAdminUser(app));
  });

  describe('Admin User Auth Tokens', () => {
    it('presence of Auth Tokens for admin ', async () => {
      expect(authTokenForAdmin).toHaveProperty('accessToken');
      expect(authTokenForAdmin).toHaveProperty('refreshToken');
    });
  });

  describe('register a new user', () => {
    const registerInput: UserRegisterInput = {
      name: 'e2etester',
      username: 'e2etester',
      password: '12345678',
      roles: [ROLE.USER],
      isAccountDisabled: false,
      email: 'e2etester@random.com',
    };

    const registerOutput = {
      id: 2,
      name: 'e2etester',
      username: 'e2etester',
      roles: [ROLE.USER],
      isAccountDisabled: false,
      email: 'e2etester@random.com',
    };

    it('successfully register a new user', () => {
      return request(app.getHttpServer())
        .post('/auth/register')
        .send(registerInput)
        .expect(HttpStatus.CREATED)
        .expect((res) => {
          const resp = res.body;
          expect(resp.data).toEqual(expect.objectContaining(registerOutput));
        });
    });

    it('register fails without Input DTO', () => {
      return request(app.getHttpServer())
        .post('/auth/register')
        .expect(HttpStatus.BAD_REQUEST);
    });

    it('register fails when incorrect username format', () => {
      registerInput.username = 12345 as any;
      return request(app.getHttpServer())
        .post('/auth/register')
        .expect(HttpStatus.BAD_REQUEST)
        .send(registerInput)
        .expect((res) => {
          const resp = res.body;
          expect(resp.error.details.message).toContain(
            'username must be a string',
          );
        });
    });
  });

  describe('login the registered user', () => {
    const loginInput: UserLoginInput = {
      username: 'e2etester',
      password: '12345678',
    };

    it('should successfully login the user', () => {
      return request(app.getHttpServer())
        .post('/auth/login')
        .send(loginInput)
        .expect(HttpStatus.OK)
        .expect((res) => {
          const token = res.body.data;
          expect(token).toHaveProperty('accessToken');
          expect(token).toHaveProperty('refreshToken');
        });
    });

    it('should failed to login with wrong credential', () => {
      return request(app.getHttpServer())
        .post('/auth/login')
        .send({ ...loginInput, password: 'wrong-pass' })
        .expect(HttpStatus.UNAUTHORIZED);
    });

    // TODO : Should fail when isAccountDisabled is set to true.
  });

  describe('refreshing jwt token', () => {
    const loginInput: UserLoginInput = {
      username: 'e2etester',
      password: '12345678',
    };

    it('should successfully get new auth token using refresh token', async () => {
      const loginResponse = await request(app.getHttpServer())
        .post('/auth/login')
        .send(loginInput);

      const token: UserAuthTokenOutput = loginResponse.body.data;
      const refreshTokenInput: RefreshTokenInput = {
        refreshToken: token.refreshToken,
      };

      return request(app.getHttpServer())
        .post('/auth/refresh-token')
        .send(refreshTokenInput)
        .expect(HttpStatus.OK)
        .expect((res) => {
          const data = res.body.data;
          expect(data).toHaveProperty('accessToken');
          expect(data).toHaveProperty('refreshToken');
        });
    });
  });

  afterAll(async () => {
    await app.close();
    await closeDBAfterTest();
  });
});
