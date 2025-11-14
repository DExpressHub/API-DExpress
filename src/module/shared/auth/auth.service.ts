import { MailerService } from '@nestjs-modules/mailer';
import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/common/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private readonly mailerService: MailerService,
  ) {}
  async validateUser(email: string, password: string) {
    const user = await this.prisma.user.findUnique({
      where: { email, isActive: true },
      include: {
        clientProfile: true,
      },
    });
    if (!user) throw new UnauthorizedException('Usuário não encontrado');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      throw new UnauthorizedException('Credenciais inválidas');
    return user;
  }
  async login(user: any) {
    const payload = {
      id: user.id,
      email: user.email,
      type: user.type,
      isActive: user.isActive,
    };

    const accessToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET,
      expiresIn: process.env.JWT_EXPIRES_IN,
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
    });

    return {
      accessToken,
      refreshToken,
      id: user.id,
      email: user.email,
      type: user.type,
      user,
    };
  }

  async refreshAccessToken(refreshToken: string) {
    try {
      const decoded = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      const id = decoded.sub || decoded.id;
      const user = await this.prisma.user.findUnique({
        where: { id },
      });

      if (!user) throw new UnauthorizedException('Usuário não encontrado');

      const payload = {
        id: user.id,
        email: user.email,
        type: user.type,
      };

      const accessToken = this.jwtService.sign(payload, {
        secret: process.env.JWT_SECRET,
        expiresIn: process.env.JWT_EXPIRES_IN,
      });

      return { accessToken };
    } catch (error) {
      throw new UnauthorizedException('Refresh token inválido ou expirado');
    }
  }

  async forgotPassword(email: string, origin: string) {
    const user = await this.prisma.user.findUnique({
      where: { email, isActive: true },
    });
    if (!user) {
      throw new NotFoundException('Usuário não encontrado.');
    }

    // Gerar token JWT com expiração
    const payload = { sub: user.id, email: user.email };
    const resetToken = this.jwtService.sign(payload, { expiresIn: '1h' });

    await this.prisma.user.update({
      where: { id: user.id },
      data: { resetToken },
    });

    // Enviar e-mail
    await this.sendPasswordResetEmail(email, resetToken);

    return { message: 'Link de recuperação enviado com sucesso.' };
  }
  async resetPassword(token: string, newPassword: string) {
    try {
      const payload = this.jwtService.verify(token);
      console.log(payload);
      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
      });
      if (!user) {
        throw new NotFoundException('Usuário não encontrado.');
      }

      if (user.resetToken !== token) {
        throw new BadRequestException('Token inválido.');
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          password: hashedPassword,
          resetToken: null,
        },
      });

      return { message: 'Senha redefinida com sucesso.' };
    } catch (error) {
      throw new BadRequestException('Token inválido ou expirado.');
    }
  }
  private async sendPasswordResetEmail(email: string, resetToken: string) {
    const resetUrl = `${process.env.PORTAL_URL}/recuperar-senha/redefinir?token=${resetToken}`;

    const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; background: #f7f9fc; border-radius: 8px; padding: 20px; color: #333;">
      <div style="text-align: center; margin-bottom: 20px;">
        <div style="font-size: 50px; text-align: center;"></div>
      </div>
      <div style="background-color: #051f42ff; padding: 15px; border-radius: 8px 8px 0 0; text-align: center;">
        <h1 style="color: #ffffff; margin: 0; font-size: 22px;">Recuperação de Senha</h1>
      </div>
      <div style="padding: 20px; background: #ffffff; border: 1px solid #e5e7eb;">
        <p style="font-size: 16px;">Olá,</p>
        <p style="font-size: 16px;">
          Recebemos uma solicitação para redefinir a senha da sua conta no <strong>Portal DExpress</strong>.
        </p>
        <p style="font-size: 16px;">
          Clique no botão abaixo para criar uma nova senha:
        </p>

        <div style="text-align: center; margin: 25px 0;">
          <a href="${resetUrl}"
             style="display: inline-block; background-color: #030c27ff; color: #ffffff; padding: 14px 28px;
                    text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px;"
             target="_blank">
            Redefinir Senha
          </a>
        </div>

        <p style="font-size: 15px; color: #e63946;">
          <strong>Importante:</strong> Este link expira em <strong>1 hora</strong>.
        </p>

        <p style="font-size: 15px;">
          Se você <strong>não solicitou</strong> esta alteração, ignore este e-mail. Sua senha permanecerá segura.
        </p>

        <hr style="border: 0; border-top: 1px solid #e5e7eb; margin: 30px 0;" />

        <p style="margin-top: 30px; font-size: 13px; color: #6b7280;">
          Este é um e-mail automático. Por favor, não responda.
        </p>
        <p style="font-size: 12px; color: #9ca3af; margin-top: 10px;">
          Portal DExpress © ${new Date().getFullYear()}
        </p>
      </div>
    </div>
  `;

    await this.mailerService.sendMail({
      to: email,
      subject: 'Redefinição de Senha - Portal DExpress',
      html: htmlContent,
    });
  }
}
