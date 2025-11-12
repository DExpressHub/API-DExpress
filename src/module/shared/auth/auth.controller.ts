import {
  Body,
  Controller,
  Post,
  Res,
  Req,
  UnauthorizedException,
  UseGuards,
  Get,
  ForbiddenException,
  Patch,
  Param,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiTags } from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';
import { Response, Request } from 'express';
import { JwtAuthGuard } from 'src/common';

const isProduction = process.env.COOKIES === 'production';

@ApiTags('Autenticação')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(
    @Body() body: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.validateUser(body.email, body.password);
    const { accessToken, refreshToken, ...userData } =
      await this.authService.login(user);

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: isProduction ? true : false,

      partitioned: isProduction ? true : false,
      sameSite: (isProduction ? 'None' : 'Lax') as 'none' | 'lax' | 'strict',
      maxAge: 5 * 60 * 60 * 1000,
    });
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: isProduction ? true : false,
      partitioned: isProduction ? true : false,
      sameSite: (isProduction ? 'None' : 'Lax') as 'none' | 'lax' | 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return { user: userData, accessToken, refreshToken };
  }

  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies?.refresh_token;

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token não fornecido');
    }

    const { accessToken } =
      await this.authService.refreshAccessToken(refreshToken);

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: isProduction ? true : false,
      partitioned: isProduction ? true : false,
      sameSite: (isProduction ? 'None' : 'Lax') as 'none' | 'lax' | 'strict',
      maxAge: 60 * 60 * 1000,
    });

    return { success: true, accessToken };
  }

  @Post('logout')
  async logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('access_token', {
      httpOnly: true,
      secure: isProduction ? true : false,
      partitioned: isProduction ? true : false,
      sameSite: (isProduction ? 'None' : 'Lax') as 'none' | 'lax' | 'strict',
    });
    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: isProduction ? true : false,
      partitioned: isProduction ? true : false,
      sameSite: (isProduction ? 'None' : 'Lax') as 'none' | 'lax' | 'strict',
    });
    return { message: 'Logout realizado com sucesso' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('validate')
  async validate(@Req() req: any) {
    return { valid: true, user: req.user };
  }
  @Post('forgot-password')
  async forgotPassword(@Body('email') email: string, @Req() req: any) {
    const originDomain =
      req.headers['origin'] ||
      req.headers['referer'] ||
      req.headers['host'] ||
      'dexpress.ao';
    return this.authService.forgotPassword(email, originDomain);
  }
  @Patch('reset-password/:token')
  async resetPassword(
    @Param('token') token: string,
    @Body('password') password: string,
  ) {
    return this.authService.resetPassword(token, password);
  }
}
