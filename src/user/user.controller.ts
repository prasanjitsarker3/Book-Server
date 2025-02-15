import {
  Controller,
  Get,
  Post,
  Body,
  HttpStatus,
  HttpCode,
  UseFilters,
  Res,
  UnauthorizedException,
  Req,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { HttpExceptionFilter } from 'src/common/filters/global-exception.filter';
import { ApiResponse } from 'src/common/dto/api-response.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Response, Request } from 'express';
import { LoginUserDto } from './dto/login-user.dtio';
import { AuthGuard } from 'src/Authentication/AuthGuard';
import { JwtUser } from 'src/Authentication/JwtUser';
import { Public } from 'src/Authentication/decorator';

@Controller('user')
@UseFilters(HttpExceptionFilter)
export class UserController {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}
  @Public()
  @Post()
  async create(
    @Body() createUserDto: CreateUserDto,
  ): Promise<ApiResponse<any>> {
    const user = await this.userService.create(createUserDto);
    return new ApiResponse(
      HttpStatus.CREATED,
      'User created successfully',
      user,
    );
  }
  @Public()
  @Post('login')
  async login(
    @Body() loginUserDto: LoginUserDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse<any>> {
    console.log('Login Body Data', loginUserDto);
    const result = await this.userService.loginUser(loginUserDto);

    res.cookie('access_token', result.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 1 * 24 * 60 * 60 * 1000,
    });

    res.cookie('refresh_token', result.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    return new ApiResponse(
      HttpStatus.OK,
      'User logged in successfully',
      result,
    );
  }

  @Public()
  @Post('refresh')
  async refreshToken(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse<any>> {
    const refreshToken = req.cookies['refresh_token'];
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    try {
      const payload = this.jwtService.verify(refreshToken);
      const newAccessToken = this.jwtService.sign(
        { sub: payload.sub, id: payload.id, email: payload.email },
        {
          expiresIn: this.configService.get<string>('accessTokenExpireDate'),
        },
      );

      res.cookie('access_token', newAccessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000,
      });

      return new ApiResponse(HttpStatus.OK, 'Token refreshed successfully', {
        access_token: newAccessToken,
      });
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  @Public()
  @Get()
  async findAll(): Promise<ApiResponse<any>> {
    const users = await this.userService.findAll();
    return new ApiResponse(
      HttpStatus.OK,
      'Users retrieved successfully',
      users,
    );
  }

  @Get('me')
  @UseGuards(AuthGuard)
  async myProfile(
    @Req() req: Request & { user: JwtUser },
  ): Promise<ApiResponse<any>> {
    const user = req.user;
    const result = await this.userService.getMyProfile(user);
    return new ApiResponse(
      HttpStatus.OK,
      'Profile retrieved successfully',
      result,
    );
  }
}
