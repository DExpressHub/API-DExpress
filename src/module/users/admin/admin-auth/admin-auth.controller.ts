import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AdminAuthService } from './admin-auth.service';
import { ApiTags, ApiOperation, ApiBody } from '@nestjs/swagger';
import { AdminLoginDto } from './dto/admin-login.dto';
import { JwtAuthGuard } from 'src/common/secret/jwt-auth.guard';
import { Response } from 'express';
import { Throttle } from '@nestjs/throttler';

const isProduction = process.env.COOKIES === 'production';

@ApiTags('Admin Auth')
@Controller('admin/auth')
export class AdminAuthController {
  constructor(private readonly service: AdminAuthService) {}

  // 🔐 LOGIN
  @Post('login')
  @Throttle({ default: { limit: 5, ttl: 30 } })
  async login(
    @Body() dto: AdminLoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken, refreshToken, user } = await this.service.login(dto);

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      maxAge: 8 * 60 * 60 * 1000,
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return { user };
  }

  // 🔁 REFRESH TOKEN
  @Post('refresh')
  async refreshToken(
    @Req() req: any,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies?.refresh_token;
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token não fornecido');
    }

    const { accessToken } = await this.service.refreshAccessToken(refreshToken);

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      maxAge: 60 * 60 * 1000,
    });

    return { success: true };
  }

  // 🚪 LOGOUT
  @Post('logout')
  async logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('access_token', {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
    });
    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
    });
    return { message: 'Logout realizado com sucesso' };
  }

  // 🔍 VALIDAR TOKEN
  @UseGuards(JwtAuthGuard)
  @Get('validate')
  async validate(@Req() req: any) {
    return { valid: true, user: req.user };
  }

  // ===============================
  // 🚨 ROTAS DE RECUPERAÇÃO DE SENHA
  // ===============================

  @Post('request-reset')
  @ApiOperation({ summary: 'Solicitar código de recuperação de senha' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'admin@empresa.com' },
      },
    },
  })
  async requestReset(@Body('email') email: string) {
    return await this.service.requestPasswordReset(email);
  }

  @Post('verify-reset')
  @ApiOperation({ summary: 'Verificar código de recuperação' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        token: { type: 'string', example: '123456' },
      },
    },
  })
  async verifyReset(@Body('token') token: string) {
    return await this.service.verifyResetToken(token);
  }

  @Post('reset-password')
  @ApiOperation({ summary: 'Redefinir senha com código de recuperação' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        token: { type: 'string', example: '123456' },
        newPassword: { type: 'string', example: 'NovaSenhaSegura123' },
      },
    },
  })
  async resetPassword(
    @Body('token') token: string,
    @Body('newPassword') newPassword: string,
  ) {
    return await this.service.resetPassword(token, newPassword);
  }
}
