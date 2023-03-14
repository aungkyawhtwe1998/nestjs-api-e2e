import { ConfigService } from '@nestjs/config';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { AuthDto } from './dto';
import { PrismaService } from './../prisma/prisma.service';
import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signup(dto: AuthDto) {
    // generate the password hash
    const hash = await argon.hash(dto.password);

    try {
      // save the ne user in the db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      // delete user.hash;
      // // return the saved user
      // return user;
      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ForbiddenException(
          'Credentials taken',
        );
      }
      // if (
      //   error instanceof
      //   PrismaClientKnownRequestError
      // ) {

      // }

      throw error;
    }
  }

  async signin(dto: AuthDto) {
    const user =
      await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      });

    if (!user)
      throw new ForbiddenException(
        'Credentials incorrect',
      );

    const pwMatches = await argon.verify(
      user.hash,
      dto.password,
    );

    if (!pwMatches) {
      throw new ForbiddenException(
        'Credentias incorrect',
      );
    }

    //delete user.hash;
    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise< {access_token: string} > {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get('JWT_SECRET');

    const token =await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });

    return { access_token: token };
  }
  
}
