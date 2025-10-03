import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { CreateProfessionalDto } from './dto/create-professional.dto';
import { UpdateProfessionalDto } from './dto/update-professional.dto';
import { FilterProfessionalDto } from './dto/filter-professional.dto'; 
import { Professional, Prisma } from '@prisma/client';
import { PaginatedDto } from 'src/common/pagination/paginated.dto'; 
import { CreateProfessionalExperienceDto } from './dto/create-professional-experience.dto';

@Injectable()
export class ProfessionalService {
  constructor(private readonly prisma: PrismaService) {}


  async create(createProfessionalDto: CreateProfessionalDto) {
    const {
      courseIds,
      languageIds,
      skillIds,
      experienceIds,
      ...professionalData
    } = createProfessionalDto;
   
    
      // 3. Verificação de usuário existente
      const existingUser = await this.findByEmail(createProfessionalDto.email);
      if (existingUser) {
        throw new BadRequestException('E-mail já cadastrado.');
      }
    

    return this.prisma.professional.create({
      data: {
        ...professionalData,
        
        professionalCourses: courseIds && courseIds.length > 0 ? {
          createMany: {
            data: courseIds.map(courseId => ({ courseId })),
          },
        } : undefined,
        professionalLanguages: languageIds && languageIds.length > 0 ? {
          createMany: {
            data: languageIds.map(languageId => ({ languageId })),
          },
        } : undefined,
        professionalSkills: skillIds && skillIds.length > 0 ? {
          createMany: {
            data: skillIds.map(skillId => ({ skillId })),
          },
        } : undefined,
        ProfessionalExperience: experienceIds && experienceIds.length > 0 ? {
          // Para um relacionamento muitos-para-muitos direto, a sintaxe `connect` funciona
          connect: experienceIds.map(id => ({ id })),
        } : undefined,
      },
      include: {
        location: { include: { city: true, district: true } },
        desiredPosition: true,
        gender: true,
        jobApplication: true,
        experienceLevel: true,
        availability: true,
        
        ProfessionalExperience: true,
        professionalCourses: { include: { course: true } },
        professionalLanguages: { include: { language: true } },
        professionalSkills: { include: { skill: true } },
        maritalStatus: true,
        highestDegree: true,
      },
    });
  }

  // ... (findAll method - remains unchanged as it's correct for its purpose) ...

  async findAll(filter: FilterProfessionalDto): Promise<PaginatedDto<Professional>> {
    const page = filter.page || 1;
    const limit = filter.limit || 10;
    const skip = (page - 1) * limit;

    const where: Prisma.ProfessionalWhereInput = {
      fullName: filter.name ? { contains: filter.name, mode: 'insensitive' } : undefined,
      location: {
        cityId: filter.cityId || undefined,
        districtId: filter.districtId || undefined,
      },
    
      experienceLevelId: filter.experienceLevelId || undefined,
      desiredPositionId: filter.desiredPositionId || undefined,
      genderId: filter.genderId || undefined,
      maritalStatusId: filter.maritalStatusId || undefined,
      highestDegreeId: filter.highestDegreeId || undefined,
      hasCriminalRecord: filter.hasCriminalRecord || undefined,
      hasMedicalCertificate: filter.hasMedicalCertificate || undefined,
      hasTrainingCertificate: filter.hasTrainingCertificate || undefined,
      hasChildren: filter.hasChildren || undefined,

      professionalCourses: filter.courseId ? { some: { courseId: filter.courseId } } : undefined,
      professionalLanguages: filter.languageId ? { some: { languageId: filter.languageId } } : undefined,
      professionalSkills: filter.skillId ? { some: { skillId: filter.skillId } } : undefined,
      ProfessionalExperience: filter.experienceId ? { some: { id: filter.experienceId } } : undefined,
    };

    const [professionals, total] = await this.prisma.$transaction([
      this.prisma.professional.findMany({
        skip,
        take: limit,
        where,
        include: {
          location: { include: { city: true, district: true } },
          desiredPosition: true,
          gender: true,
          jobApplication: true,
          experienceLevel: true,
          maritalStatus: true,
          highestDegree: true,
          availability: true,
          
          ProfessionalExperience: true,
          professionalCourses: { include: { course: true } },
          professionalLanguages: { include: { language: true } },
          professionalSkills: { include: { skill: true } },
        },
      }),
      this.prisma.professional.count({ where }),
    ]);

    const totalPages = Math.ceil(total / limit);

    return {
      data: professionals,
      total,
      page,
      limit,
      totalPages,
    };
  }
  async getPublicProfessionals(filter: FilterProfessionalDto): Promise<PaginatedDto<Professional>> {
    const page = filter.page || 1;
    const limit = filter.limit || 10;
    const skip = (page - 1) * limit;

    const where: Prisma.ProfessionalWhereInput = {
      fullName: filter.name ? { contains: filter.name, mode: 'insensitive' } : undefined,
      location: {
        cityId: filter.cityId || undefined,
        districtId: filter.districtId || undefined,
      },
    
      experienceLevelId: filter.experienceLevelId || undefined,
      desiredPositionId: filter.desiredPositionId || undefined,
      genderId: filter.genderId || undefined,
      maritalStatusId: filter.maritalStatusId || undefined,
      highestDegreeId: filter.highestDegreeId || undefined,
      hasCriminalRecord: filter.hasCriminalRecord || undefined,
      hasMedicalCertificate: filter.hasMedicalCertificate || undefined,
      hasTrainingCertificate: filter.hasTrainingCertificate || undefined,
      hasChildren: filter.hasChildren || undefined,

      professionalCourses: filter.courseId ? { some: { courseId: filter.courseId } } : undefined,
      professionalLanguages: filter.languageId ? { some: { languageId: filter.languageId } } : undefined,
      professionalSkills: filter.skillId ? { some: { skillId: filter.skillId } } : undefined,
      ProfessionalExperience: filter.experienceId ? { some: { id: filter.experienceId } } : undefined,
      isAvailable:true
    };

    const [professionals, total] = await this.prisma.$transaction([
      this.prisma.professional.findMany({
        
        skip,
        take: limit,
        where,
        include: {
          location: { include: { city: true, district: true } },
          desiredPosition: true,
          gender: true,
  
          experienceLevel: true,
          maritalStatus: true,
          highestDegree: true,
      
         
        },
      }),
      this.prisma.professional.count({ where }),
    ]);

    const totalPages = Math.ceil(total / limit);

    return {
      data: professionals,
      total,
      page,
      limit,
      totalPages,
    };
  }

 async findAllForDropdown(): Promise<Professional[]> {
    return this.prisma.professional.findMany({
      where: { isAvailable: true },
     
      orderBy: {
        fullName: 'asc',
      },
    });
  }


  // ... (findOne method - remains unchanged as it's correct for its purpose) ...

  async findOne(id: string) {
    const professional = await this.prisma.professional.findUnique({
      where: { id },
      include: {
        location: { include: { city: true, district: true } },
        desiredPosition: true,
        gender: true,
      
        experienceLevel: true,
        maritalStatus: true,
        highestDegree: true,
        availability: true,
        contract:{
          select: {
            id: true,
            status: true,
            contractNumber: true,
            startDate: true,
            endDate: true,
            clientType: true,
            individualClient: {
              select: {
                id: true,
                fullName: true,
                email: true,
                phoneNumber: true
              }
            },
        
          }
        },
        contractPackegeProfissional:{
          include:{
           contract: {
  select: {
    id: true,
    status: true,
    contractNumber: true,
    startDate: true,
    endDate: true,
    clientType: true,
    individualClient: {
      select: {
        id: true,
        fullName: true,
        email: true,
        phoneNumber: true
      }
    },
    companyClient: true
  }
}
}
        },
       
        
        ProfessionalExperience: true,
        professionalCourses: { include: { course: true } },
        professionalLanguages: { include: { language: true } },
        professionalSkills: { include: { skill: true } },
      },
    });

    return professional;
  }

  

  /**
   * Atualiza um profissional existente. As relações many-to-many são sincronizadas.
   * Para tabelas de junção explícitas, isso envolve deletar as entradas antigas
   * e criar as novas.
   * @param id O ID do profissional a ser atualizado (UUID em string).
   * @param updateProfessionalDto O DTO com os dados a serem atualizados.
   * @returns O profissional atualizado.
   * @throws NotFoundException se o profissional não for encontrado.
   */
  async update(id: string, updateProfessionalDto: UpdateProfessionalDto) {
    const {
      courseIds,
      languageIds,
      skillIds,
      experienceIds,
      ...professionalData
    } = updateProfessionalDto;

    try {
      // Use um $transaction para garantir que todas as operações sejam atômicas
      return await this.prisma.$transaction(async (prisma) => {
        // 1. Atualiza os dados diretos do profissional
        const updatedProfessional = await prisma.professional.update({
          where: { id },
          data: {
            ...professionalData,
            // O relacionamento ProfessionalExperience é um many-to-many direto,
            // então 'set' funciona aqui.
            ProfessionalExperience: experienceIds && experienceIds.length > 0 ? {
              set: experienceIds.map(experienceId => ({ id: experienceId })),
            } : { set: [] },
          },
        });

        // 2. Sincroniza as tabelas de junção (ProfessionalCourses, ProfessionalLanguages, ProfessionalSkills)
        // Para cada uma, deletamos as entradas antigas e criamos as novas.

        // ProfessionalCourses
        await prisma.professionalCourses.deleteMany({
          where: { professionalId: id },
        });
        if (courseIds && courseIds.length > 0) {
          await prisma.professionalCourses.createMany({
            data: courseIds.map(courseId => ({ professionalId: id, courseId })),
          });
        }

        // ProfessionalLanguages
        await prisma.professionalLanguages.deleteMany({
          where: { professionalId: id },
        });
        if (languageIds && languageIds.length > 0) {
          await prisma.professionalLanguages.createMany({
            data: languageIds.map(languageId => ({ professionalId: id, languageId })),
          });
        }

        // ProfessionalSkills
        await prisma.professionalSkills.deleteMany({
          where: { professionalId: id },
        });
        if (skillIds && skillIds.length > 0) {
          await prisma.professionalSkills.createMany({
            data: skillIds.map(skillId => ({ professionalId: id, skillId })),
          });
        }

        // 3. Retorna o profissional atualizado com as relações incluídas
        return prisma.professional.findUnique({
          where: { id },
          include: {
            location: { include: { city: true, district: true } },
            desiredPosition: true,
            gender: true,
            jobApplication: true,
            experienceLevel: true,
            maritalStatus: true,
            highestDegree: true,
            professionalCourses: { include: { course: true } },
            professionalLanguages: { include: { language: true } },
            professionalSkills: { include: { skill: true } },
            ProfessionalExperience: true,
          },
        });
      });
    } catch (error) {
      if (error.code === 'P2025') {
        throw new NotFoundException(`Professional with ID "${id}" not found`);
      }
      throw error;
    }
  }



  /**
   * Remove um profissional do banco de dados.
   * @param id O ID do profissional a ser removido (UUID em string).
   * @returns O profissional que foi removido.
   * @throws NotFoundException se o profissional não for encontrado.
   */
  async remove(id: string) {
    try {
      return await this.prisma.professional.delete({ where: { id } });
    } catch (error) {
      if (error.code === 'P2025') {
        throw new NotFoundException(`Professional with ID "${id}" not found`);
      }
      throw error;
    }
  }
    /**
   * Busca um profissional pelo endereço de e-mail.
   * @param email O e-mail do profissional a ser encontrado.
   * @returns O objeto do profissional, incluindo suas relações, se encontrado.
   * @throws NotFoundException se o profissional com o e-mail fornecido não for encontrado.
   */
  async findByEmail(email: string) {
    const professional = await this.prisma.professional.findUnique({
      where: { email },
      include: {
       location: { include: { city: true, district: true } },
            desiredPosition: true,
            gender: true,
            jobApplication: true,
            experienceLevel: true,
            maritalStatus: true,
            highestDegree: true,
            professionalCourses: { include: { course: true } },
            professionalLanguages: { include: { language: true } },
            professionalSkills: { include: { skill: true } },
            ProfessionalExperience: true,
      },
    });

 
    
    return professional;
  }
  /**
   * Atualiza especificamente o status de disponibilidade de um profissional.
   * @param id O ID do profissional.
   * @param isAvailable O novo estado de disponibilidade (true ou false).
   * @returns O objeto Professional atualizado.
   */
async updateAvailability(id: string, isAvailable: boolean): Promise<Professional> {
  const professional = await this.prisma.professional.findUnique({
    where: { id },
    include: {
      contract: {
        where: { status: 'ACTIVE' },
        select: { id: true },
      },
      contractPackegeProfissional: {
        where: { isActive: true },
        select: { id: true },
      },
    },
  });

  if (!professional) {
    throw new NotFoundException(`Profissional com ID "${id}" não encontrado.`);
  }

  // Verifica contratos ativos diretos ou via package
  const hasActiveDirect = professional.contract.length > 0;
  const hasActivePackage = professional.contractPackegeProfissional.some(
    (cp) => cp.id !== null
  );

  if (isAvailable && (hasActiveDirect || hasActivePackage)) {
    throw new BadRequestException(
      `O profissional não pode estar disponível enquanto tiver contratos ativos.`
    );
  }

  return this.prisma.professional.update({
    where: { id },
    data: { isAvailable },
  });
}


    async updateImageUrl(id: string, profileImage: string): Promise<Professional> {
    const professional = await this.prisma.professional.findUnique({ where: { id } });
    if (!professional) {
      throw new NotFoundException(`Profissional com ID "${id}" não encontrado.`);
    }

    return this.prisma.professional.update({
      where: { id },
      data: { profileImage }, 
    });
  }
  async  addExperienceToProfessional(dto:CreateProfessionalExperienceDto,professionalId:string) {
   const professional = await this.prisma.professional.findUnique({ where: { id:professionalId } });
    if (!professional) {
      throw new NotFoundException(`Profissional com ID "${professionalId}" não encontrado.`);
    }
    return await this.prisma.experience.create({
      data: {
        ...dto,
        Professional: {
          connect: { id: professionalId }
        }
      },
      include: {
        Professional: true
      }
    });
  
    
 
}
/**
 * Remove a ligação de uma experiência a um profissional e, se a experiência não
 * estiver mais ligada a ninguém, a remove completamente do banco de dados.
 *
 * @param professionalId O ID do profissional.
 * @param experienceId O ID da experiência a ser removida.
 * @returns O objeto da experiência que foi removida (ou desconectada).
 * @throws NotFoundException Se a experiência ou o profissional não forem encontrados.
 */
async removeExperienceFromProfessional(professionalId: string, experienceId: string) {
  // 1. Verifica se o profissional e a experiência existem para garantir que os IDs são válidos.
  const professional = await this.prisma.professional.findUnique({
    where: { id: professionalId }
  });

  const experience = await this.prisma.experience.findUnique({
    where: { id: experienceId }
  });

  if (!professional) {
    throw new NotFoundException(`Profissional com ID "${professionalId}" não encontrado.`);
  }

  if (!experience) {
    throw new NotFoundException(`Experiência com ID "${experienceId}" não encontrada.`);
  }

  // 2. Desconecta a experiência do profissional. Isso remove a entrada na tabela de junção.
  await this.prisma.professional.update({
    where: { id: professionalId },
    data: {
      ProfessionalExperience: {
        disconnect: { id: experienceId }
      }
    }
  });

  // 3. Conta quantos profissionais ainda têm essa experiência associada.
  const experienceConnectionsCount = await this.prisma.professional.count({
    where: {
      ProfessionalExperience: {
        some: {
          id: experienceId
        }
      }
    }
  });

  // 4. Se a contagem for zero, significa que a experiência não está ligada a mais ninguém.
  //    Nesse caso, podemos deletar o registro da experiência.
  if (experienceConnectionsCount === 0) {
    return await this.prisma.experience.delete({
      where: { id: experienceId }
    });
  }

  // Se a experiência ainda tiver conexões, apenas retorne o objeto da experiência.
  return experience;
}


}