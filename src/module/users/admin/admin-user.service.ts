import { Injectable, ForbiddenException, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/common/prisma/prisma.service'; // Ajuste o caminho conforme o seu projeto
import * as bcrypt from 'bcrypt';

import { MailerService } from '@nestjs-modules/mailer';
import { AdminUser, Prisma } from '@prisma/client';
import { FindAllDto } from 'src/common/pagination/find-all.dto';
import { PaginatedDto } from 'src/common/pagination/paginated.dto';

import { UpdateAdminUserDto } from './dto/update-admin.dto';
import { CreateAdminUserDto } from './dto/create-admin-user.dto.ts';
import { AuditLogService } from 'src/module/shared/auditLog/auditLog.service';

@Injectable()
export class AdminUserService {
  constructor(private readonly prisma: PrismaService, private readonly mailerService: MailerService, private readonly auditLogService: AuditLogService,) {}

  /**
   * Cria um novo utilizador administrador.
   * Apenas o Admin Geral pode executar esta ação.
   * @param dto DTO com os dados do novo administrador.
   * @param creatorId ID do utilizador que está a criar.
   * @returns Mensagem de sucesso e o ID do novo administrador.
   */
  async create(dto: CreateAdminUserDto, creatorId: string,originDomain:any) {
    // 1. Verifica se quem cria é um Admin Geral
    const creator = await this.prisma.adminUser.findUnique({ where: { id: creatorId } });
    if (!creator) {
      throw new ForbiddenException('Somente o Admin Geral pode criar novos administradores.');
    }

    // 2. Verifica duplicidade de email ou identidade
    const existing = await this.prisma.adminUser.findFirst({
      where: { OR: [{ email: dto.email }, { identityNumber: dto.identityNumber }] },
    });
    if (existing) {
      throw new ForbiddenException('Administrador já existe com este email ou número de identidade.');
    }

    // 3. Verifica se o perfil existe
    const profile = await this.prisma.profile.findUnique({ where: { id: dto.profileId } });
    if (!profile) {
      throw new NotFoundException(`Perfil com o ID "${dto.profileId}" não encontrado.`);
    }

    // 4. Gera senha segura caso não tenha sido fornecida
    const password = dto.password || Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(password, 10);

    // 5. Cria o novo admin na base de dados, conectando ao perfil
    const newAdmin = await this.prisma.adminUser.create({
      data: {
        name: dto.name,
        numberphone: dto.numberphone,
        identityNumber: dto.identityNumber,
        genderId: dto.genderId,
        birthDate: dto.birthDate,
        email: dto.email,
        password: hashedPassword,
       
        profileId: dto.profileId,
      },
      include: { 
        profile: { include: { permissions: true } }, 
        gender: true 
      },
    });

    // 6. Envia o email de boas-vindas
    await this.sendAdminWelcomeEmail(newAdmin.email, password,originDomain,profile.label);
      // 🔹 Log de auditoria
    await this.auditLogService.createLog({
      action: 'CREATE_ADMIN',
      entity: 'AdminUser',
      entityId: newAdmin.id,
      description: `Administrador ${newAdmin.name} criado por ${creator.name}`,
      newData: newAdmin,
      status: 'SUCCESS',
      source: 'USER',
      userId: creatorId,
    });
    return { message: 'Administrador criado com sucesso', id: newAdmin.id };
  }
  
  /**
   * Busca e retorna dados do perfil de um administrador.
   * @param userId ID do administrador.
   * @returns Objeto com os dados do perfil, sem a senha.
   */
  async getProfileData(userId: string) {
    if (!userId) {
      throw new ForbiddenException('Utilizador não autenticado ou ID inválido');
    }
    
    const admin = await this.prisma.adminUser.findUnique({
      where: { id: userId },
      include: { 
        profile: {
          
          include: {
            permissions: true,
          },
        },
        
      
        notificationSettings: true, 
        securitySettings: true,
        gender: true, 
      },
    });

    if (!admin) {
      throw new ForbiddenException('Administrador não encontrado');
    }

    // Monta a resposta (escondendo a senha por segurança)
  return admin
  }
  
  /**
   * Busca todos os utilizadores administradores com paginação e filtro.
   * @param query DTO com os parâmetros de pesquisa, página e limite.
   * @returns Lista paginada de utilizadores.
   */
  async findAll(query: FindAllDto): Promise<PaginatedDto<AdminUser>> {
    const page = query.page || 1;
    const limit = query.limit || 10;
    const skip = (page - 1) * limit;

    const where: Prisma.AdminUserWhereInput = query.search
      ? {
          OR: [
            { name: { contains: query.search, mode: 'insensitive' } },
            { email: { contains: query.search, mode: 'insensitive' } },
          ],
        }
      : {};

    const [users, total] = await this.prisma.$transaction([
      this.prisma.adminUser.findMany({
        skip,
        take: limit,
        where,
        include: {
          gender: true,
          profile: true, // ✅ Incluindo o perfil
        },
      }),
      this.prisma.adminUser.count({ where }),
    ]);

    const totalPages = Math.ceil(total / limit);

    return {
      data: users,
      total,
      page,
      limit,
      totalPages,
    } as PaginatedDto<AdminUser>;
  }

  /**
   * Busca um único utilizador administrador pelo ID.
   * @param id ID do utilizador.
   * @returns O objeto do utilizador.
   */
  async findOne(id: string): Promise<AdminUser> {
    const user = await this.prisma.adminUser.findUnique({
      where: { id },
      include: {
        gender: true,
        profile: true, // ✅ Incluindo o perfil
      },
    });

    if (!user) {
      throw new NotFoundException(`Utilizador com o ID "${id}" não encontrado`);
    }
    return user;
  }

  /**
   * Atualiza um utilizador administrador.
   * @param id ID do utilizador.
   * @param updateAdminUserDto DTO com os dados a serem atualizados.
   * @returns O objeto do utilizador atualizado.
   */
  async update(id: string, updateAdminUserDto: UpdateAdminUserDto): Promise<AdminUser> {
    const oldAdmin = await this.prisma.adminUser.findUnique({ where: { id } });
    if (!oldAdmin) throw new NotFoundException(`Utilizador com o ID "${id}" não encontrado`);

    const updateData: Prisma.AdminUserUpdateInput = {};
    for (const [key, value] of Object.entries(updateAdminUserDto)) {
      if (value !== undefined && key !== 'profileId') {
        updateData[key as keyof Prisma.AdminUserUpdateInput] = value;
      }
    }

    if (updateAdminUserDto.profileId) {
      const profile = await this.prisma.profile.findUnique({ where: { id: updateAdminUserDto.profileId } });
      if (!profile) throw new NotFoundException(`Perfil com o ID "${updateAdminUserDto.profileId}" não encontrado.`);
      updateData.profile = { connect: { id: updateAdminUserDto.profileId } };
    }

    const updated = await this.prisma.adminUser.update({ where: { id }, data: updateData });

    // 🔹 Log de auditoria
    await this.auditLogService.createLog({
      action: 'UPDATE_ADMIN',
      entity: 'AdminUser',
      entityId: id,
      description: `Administrador ${updated.name} atualizado`,
      previousData: oldAdmin,
      newData: updated,
      status: 'SUCCESS',
      source: 'USER',
      userId: updated.id,
    });

    return updated;
  }


  /**
   * Remove um utilizador administrador.
   * @param id ID do utilizador.
   * @returns O objeto do utilizador removido.
   */
  async remove(id: string,deletor:string): Promise<AdminUser> {
    const adminDelete = await this.prisma.adminUser.findUnique({ where: { id } });
    if (!adminDelete) throw new NotFoundException(`Utilizador com o ID "${id}" não encontrado`);
    if (adminDelete?.isRoot) throw new NotFoundException(`Utilizador "${adminDelete?.name}" não pode ser deletado`);
    if (adminDelete?.id === deletor) throw new NotFoundException(`Você não pode se auto deletar`);
    if(adminDelete?.profileId){
      const CurrentUser = await this.prisma.adminUser.findUnique({ where: { id: deletor } });
    if(adminDelete.profileId === CurrentUser?.profileId && CurrentUser?.isRoot === false){
        throw new NotFoundException(`Somente outro Admin Geral pode deletar este usuário`);
      }
    }

    const deleted = await this.prisma.adminUser.delete({ where: { id } });

    // 🔹 Log de auditoria
    await this.auditLogService.createLog({
      action: 'DELETE_ADMIN',
      entity: 'AdminUser',
      entityId: id,
      description: `Administrador ${deleted.name} foi removido`,
      previousData: adminDelete,
      status: 'SUCCESS',
      source: 'USER',
      userId: deletor,
     
    });

    return deleted;
  }

  async updateImageUrl(id: string, avatar: string): Promise<AdminUser> {
    const admin = await this.prisma.adminUser.findUnique({ where: { id } });
    if (!admin) throw new NotFoundException(`User com ID "${id}" não encontrado.`);

    const updated = await this.prisma.adminUser.update({
      where: { id },
      data: { avatar },
    });

    // 🔹 Log de auditoria
    await this.auditLogService.createLog({
      action: 'UPDATE_AVATAR',
      entity: 'AdminUser',
      entityId: id,
      description: `Imagem de perfil do administrador ${updated.name} atualizada`,
      previousData: { avatar: admin.avatar },
      newData: { avatar: updated.avatar },
      status: 'SUCCESS',
      source: 'USER',
      userId: id,
    });

    return updated;
  }

  /**
   * Envia um email de boas-vindas com credenciais temporárias para o administrador.
   * @param adminEmail O email do administrador.
   * @param tempPassword A senha temporária.
   */
  async sendAdminWelcomeEmail(adminEmail: string, tempPassword: string,originDomain:any,perfil:string) {
    const dashboardUrl = originDomain
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; background: #f7f9fc; border-radius: 8px; padding: 20px; color: #333;">
        <div style="text-align: center; margin-bottom: 20px;">
              <div style="font-size: 50px; text-align: center;">🛠️</div>
        </div>
        <div style="background-color: #051f42ff; padding: 15px; border-radius: 8px 8px 0 0; text-align: center;">
          <h1 style="color: #ffffff; margin: 0; font-size: 22px;">Acesso ao Painel Administrativo</h1>
        </div>
        <div style="padding: 20px; background: #ffffff; border: 1px solid #e5e7eb;">
          <p style="font-size: 16px;">Olá,</p>
          <p style="font-size: 16px;">
            Sua conta de <strong>${perfil}</strong> foi criada com sucesso!  
            Utilize as credenciais abaixo para acessar o painel administrativo.
          </p>

          <div style="background: #f3f4f6; padding: 15px; border-radius: 5px; margin: 15px 0; font-size: 16px;">
            <strong>E-mail:</strong> ${adminEmail} <br/>
            <strong>Senha Temporária:</strong> ${tempPassword}
          </div>

          <p style="font-size: 15px;">
            Por questões de segurança, altere sua senha assim que acessar o sistema.
          </p>

          <a href="${dashboardUrl}" 
          style="display: inline-block; background-color: #051f42ff; color: #ffffff; padding: 12px 24px; 
                      text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px; margin-top: 20px;"
          target="_blank">
            Acessar Painel
          </a>

          <p style="margin-top: 30px; font-size: 13px; color: #6b7280;">
            Este e-mail é automático. Não responda a esta mensagem.
          </p>
        </div>
      </div>`;

    await this.mailerService.sendMail({
      to: adminEmail,
      subject: 'Credenciais do Painel Administrativo - DExpress',
      html: htmlContent,
    });
  }
}
