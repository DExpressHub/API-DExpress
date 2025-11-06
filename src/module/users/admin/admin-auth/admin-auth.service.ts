import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/common/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { AdminLoginDto } from './dto/admin-login.dto';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class AdminAuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly mailerService: MailerService,
  ) {}

  async login(dto: AdminLoginDto) {
    // ✅ Incluir o perfil e as permissões dentro dele
    const admin = await this.prisma.adminUser.findUnique({
      where: { email: dto.email ,isActive:true},
      include: {
        profile: {
          include: {
            permissions: true,
          },
        },
      },
    });

    if (!admin || !(await bcrypt.compare(dto.password, admin.password))) {
      throw new UnauthorizedException('Credenciais inválidas');
    }
    // ✅ Mapear as permissões a partir do perfil
    const permissionNames = admin.profile?.permissions.map((p) => p.name) || [];
    const payload = {
      id: admin.id,
      email: admin.email,
      name: admin.name,
      role: admin.profile.label,
      avatar:admin.avatar,
      permissions: permissionNames,
    };
    const accessToken = this.jwt.sign(payload, {
      secret: process.env.JWT_SECRET,
      expiresIn: process.env.JWT_EXPIRES_IN,
    });

    const refreshToken = this.jwt.sign(payload, {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN, 
    });

    return {
      accessToken,
      refreshToken,
      user: {
        id: admin.id,
        name: admin.name,
        email: admin.email,
        role: admin.profile.label,
        avatar:admin.avatar,
        permissions: permissionNames,
      },
    };
  }

  async refreshAccessToken(refreshToken: string) {
    try {
      const decoded = this.jwt.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      // ✅ Incluir o perfil e as permissões dentro dele
      const admin = await this.prisma.adminUser.findUnique({
        where: { id: decoded.sub },
        include: {
          profile: {
            include: {
              permissions: true,
            },
          },
        },
      });

      if (!admin) throw new UnauthorizedException('Admin não encontrado');

      // ✅ Mapear as permissões a partir do perfil
      const permissionNames = admin.profile?.permissions.map((p) => p.name) || [];

      const payload = {
        sub: admin.id,
        email: admin.email,
        role: admin.profile.label,
         avatar:admin.avatar,
        permissions: permissionNames,
      };

      const accessToken = this.jwt.sign(payload, {
        secret: process.env.JWT_SECRET,
        expiresIn: process.env.JWT_EXPIRES_IN,
      });

      return { accessToken };
    } catch (error) {
      throw new UnauthorizedException('Refresh token inválido ou expirado');
    }
  }

async requestPasswordReset(email: string) {
  const user = await this.prisma.adminUser.findUnique({ where: { email } });
  if (!user) throw new BadRequestException("Usuário não encontrado.");

  // Gera token único
const token = Math.floor(100000 + Math.random() * 900000).toString();
  // Define expiração (15 minutos)
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

  // Salva no banco
  await this.prisma.passwordResetToken.create({
    data: {
      userId: user.id,
      token,
      expiresAt,
    },
  });
  await this.sendPasswordResetVerificationCode(user.email, token);

  // Envia por e-mail
  console.log(`Envie este código: ${token}`);

  return { message: "Código de recuperação enviado com sucesso." };
}

  async verifyResetToken(token: string) {
    const reset = await this.prisma.passwordResetToken.findUnique({
      where: { token },
    });

    if (!reset) throw new BadRequestException("Código inválido.");
    if (reset.used) throw new BadRequestException("Código já utilizado.");
    if (reset.expiresAt < new Date()) throw new BadRequestException("Código expirado.");

    return { valid: true, userId: reset.userId };
  }

  async resetPassword(token: string, newPassword: string) {
    const verification = await this.verifyResetToken(token);
    if(!verification) return new BadRequestException("Código inválido.")
    const hashed = await bcrypt.hash(newPassword, 10);
    // Atualiza senha do usuário
    await this.prisma.adminUser.update({
      where: { id: verification.userId },
      data: { password: hashed },
    });
    console.log(verification.userId,"DATA", new Date());
    

    // Atualiza data de última mudança
    const secure_settings = await this.prisma.securitySettings.findUnique({where:{userId:verification.userId}})
    if(!secure_settings){
      await this.prisma.securitySettings.create({
        data:{
          userId:verification.userId 
        }
      })


    }else{
       await this.prisma.securitySettings.update({
      where: { userId: verification.userId },
      data: { lastPasswordChange: new Date() },
    });

    }
   

    // Marca o token como usado
    await this.prisma.passwordResetToken.update({
      where: { token },
      data: { used: true },
    });

    return { message: "Senha redefinida com sucesso." };
  }
  async sendPasswordResetVerificationCode(userEmail: string, verificationCode: string) {
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; background: #f7f9fc; border-radius: 8px; padding: 20px; color: #333;">
        <div style="text-align: center; margin-bottom: 20px;">
              <div style="font-size: 50px; text-align: center;">🔒</div>
        </div>
        <div style="background-color: #051f42ff; padding: 15px; border-radius: 8px 8px 0 0; text-align: center;">
          <h1 style="color: #ffffff; margin: 0; font-size: 22px;">Solicitação de Alteração de Senha</h1>
        </div>
        <div style="padding: 20px; background: #ffffff; border: 1px solid #e5e7eb;">
          <p style="font-size: 16px;">Olá,</p>
          <p style="font-size: 16px;">
            Você solicitou a alteração de sua senha. Use o **código de verificação** abaixo para confirmar sua identidade.
          </p>

          <div style="background: #f3f4f6; padding: 20px; border-radius: 5px; margin: 25px 0; text-align: center;">
            <strong style="font-size: 18px; color: #6b7280;">Seu Código de Verificação é:</strong>
            <div style="font-size: 32px; font-weight: bold; color: #051f42ff; margin-top: 10px; letter-spacing: 5px;">
              ${verificationCode}
            </div>
          </div>

          <p style="font-size: 15px;">
            Este código é válido por um tempo limitado (ex: 15 minutos). Não o compartilhe com ninguém.
          </p>
          <p style="font-size: 15px; margin-top: 20px;">
            Se você **não** solicitou esta alteração, por favor, ignore este e-mail. Sua senha atual permanecerá inalterada.
          </p>

          <p style="margin-top: 30px; font-size: 13px; color: #6b7280;">
            Este e-mail é automático. Não responda a esta mensagem.
          </p>
        </div>
      </div>`;

    await this.mailerService.sendMail({
      to: userEmail,
      subject: 'Código de Verificação de Alteração de Senha',
      html: htmlContent,
    });
}

}
