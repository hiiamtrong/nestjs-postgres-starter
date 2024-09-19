import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Get,
  HttpStatus,
  Param,
  Patch,
  Query,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Permissions } from 'src/auth/decorators/permissions.decorator';
import { JwtOperatorAuthGuard } from 'src/auth/guards/jwt-operator-auth.guard';
import { USER_PERMISSIONS } from 'src/permission/permission.constant';

import { PermissionsGuard } from '../../auth/guards/permissions.guard';
import {
  BaseApiErrorResponse,
  BaseApiResponse,
  SwaggerBaseApiResponse,
} from '../../shared/dtos/base-api-response.dto';
import { PaginationParamsDto } from '../../shared/dtos/pagination-params.dto';
import { AppLogger } from '../../shared/logger/logger.service';
import { ReqContext } from '../../shared/request-context/req-context.decorator';
import { RequestContext } from '../../shared/request-context/request-context.dto';
import { UserOutput } from '../dtos/user-output.dto';
import { BackofficeUpdateUserInput } from '../dtos/user-update.dto';
import { UserService } from '../services/user.service';

@ApiBearerAuth()
@ApiTags('Backoffice/Users')
@Controller('backoffice/users')
@UseGuards(JwtOperatorAuthGuard, PermissionsGuard)
export class BackOfficeUserController {
  constructor(
    private readonly userService: UserService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(BackOfficeUserController.name);
  }

  @UseInterceptors(ClassSerializerInterceptor)
  @Get()
  @ApiOperation({
    summary: 'Get users as a list API',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    type: SwaggerBaseApiResponse([UserOutput]),
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    type: BaseApiErrorResponse,
  })
  @Permissions(USER_PERMISSIONS.MANAGE, USER_PERMISSIONS.READ)
  async getUsers(
    @ReqContext() ctx: RequestContext,
    @Query() query: PaginationParamsDto,
  ): Promise<BaseApiResponse<UserOutput[]>> {
    this.logger.log(ctx, `${this.getUsers.name} was called`);

    const { users, count } = await this.userService.getUsers(
      ctx,
      query.limit,
      query.offset,
    );

    return { data: users, meta: { count } };
  }

  @Permissions(USER_PERMISSIONS.MANAGE, USER_PERMISSIONS.READ)
  @UseInterceptors(ClassSerializerInterceptor)
  @Get(':id')
  @ApiOperation({
    summary: 'Get user by id API',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    type: SwaggerBaseApiResponse(UserOutput),
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    type: BaseApiErrorResponse,
  })
  async getUser(
    @ReqContext() ctx: RequestContext,
    @Param('id') id: number,
  ): Promise<BaseApiResponse<UserOutput>> {
    this.logger.log(ctx, `${this.getUser.name} was called`);

    const user = await this.userService.getUserById(ctx, id);
    return { data: user, meta: {} };
  }

  @Patch(':id')
  @ApiOperation({
    summary: 'Update user API',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    type: SwaggerBaseApiResponse(UserOutput),
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    type: BaseApiErrorResponse,
  })
  @UseInterceptors(ClassSerializerInterceptor)
  @Permissions(USER_PERMISSIONS.MANAGE, USER_PERMISSIONS.UPDATE)
  async updateUser(
    @ReqContext() ctx: RequestContext,
    @Param('id') userId: number,
    @Body() input: BackofficeUpdateUserInput,
  ): Promise<BaseApiResponse<UserOutput>> {
    this.logger.log(ctx, `${this.updateUser.name} was called`);

    const user = await this.userService.updateUser(ctx, userId, input);
    return { data: user, meta: {} };
  }
}
