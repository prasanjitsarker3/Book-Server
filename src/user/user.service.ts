// src/user/user.service.ts
import {
  Injectable,
  ConflictException,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dtio';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtUser } from 'src/Authentication/JwtUser';

@Injectable()
export class UserService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}
  async create(createUserDto: CreateUserDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: createUserDto.email },
    });

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const hashPassword = await bcrypt.hash(createUserDto.password, 12);
    try {
      const user = await this.prisma.user.create({
        data: {
          name: createUserDto.name,
          email: createUserDto.email,
          password: hashPassword,
        },
        select: {
          name: true,
          email: true,
        },
      });

      return user;
    } catch (error) {
      throw new InternalServerErrorException('Failed to create user');
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('User Not Found !');
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const payload = { sub: user.id, id: user.id, email: user.email };
    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: this.configService.get<string>('accessTokenExpireDate'),
    });

    const refreshToken = await this.jwtService.signAsync(payload, {
      expiresIn: this.configService.get<string>('refreshTokenExpireDate'),
    });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async findAll() {
    try {
      const users = await this.prisma.user.findMany({
        select: {
          id: true,
          name: true,
          email: true,
        },
      });
      return users;
    } catch (error) {
      throw new InternalServerErrorException('Failed to retrieve users');
    }
  }

  async getMyProfile(user: JwtUser) {
    return this.prisma.user.findUniqueOrThrow({
      where: {
        email: user.email,
      },
    });
  }
}
