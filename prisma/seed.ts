import { PrismaClient } from '@prisma/client';
import { districtNames } from './seeds/distritos.seed';
import { desiredPositionData } from './seeds/DesiredPosition.seed';
import { genderData } from './seeds/Gender.seed';
import { maritalStatusData } from './seeds/MaritalStatus.seed';
import { highestDegreeData } from './seeds/HighestDegree.seed';
import { courseData } from './seeds/Course.seed';
import { languageData } from './seeds/Language.seed';
import { skillData } from './seeds/Skill.seed';
import { sectorNames } from './seeds/Sector.seed';

import { experienceLevelData } from './seeds/experincial-level.seed';
import { internalPermissions } from './seeds/permission.seed';

import * as bcrypt from 'bcrypt';
import { profilesData } from './seeds/perfil.seed';
import { packageSeeds } from './seeds/Package.seed';

const prisma = new PrismaClient();

async function main() {
  console.log(`Iniciando o seeding...`);

  // --- SEED: DADOS GERAIS (CIDADE, ESPECIALIDADES, etc.) ---
  // O código para estas seções permanece inalterado.
  // ... (o seu código original para city, district, specialty, etc. vai aqui)
  // --- SEED: CIDADE E DISTRITOS ---
  const luanda = await prisma.city.upsert({
    where: { name: 'Luanda' },
    update: {},
    create: { name: 'Luanda' },
  });

  const districtMap: Record<string, string> = {};
  for (const name of districtNames) {
    const district = await prisma.district.upsert({
      where: { name_cityId: { name, cityId: luanda.id } },
      update: {},
      create: { name, cityId: luanda.id },
    });
    districtMap[name] = district.id;
  }
  console.log('✅ Cidade "Luanda" e distritos criados com sucesso!');


  // --- SEED: SETORES DE EMPRESA ---
  const sectorMap: Record<string, string> = {};
  for (const data of sectorNames) {
    const sector = await prisma.sector.upsert({
        where: { name: data.name },
      update: {},
      create: data,
    
    });
    sectorMap[data.name] = sector.id;
  }
  console.log('✅ Setores de empresa criados com sucesso!');

   
   const urls = [
    "https://dexpress.ao",
    "https://backoffice.dexpress.ao",
    "https://back-office-d-express.vercel.app",
    "https://web-site-d-express.vercel.app"
  ];

  for (const url of urls) {
    await prisma.frontendUrl.upsert({
      where: { url: url },
      update: {},
      create: { url: url },
    });
  }
  console.log('Frontend URLs seeded!');


 console.log('Iniciando o seeding de pacotes...');

  const packageMap: Record<string, string> = {};

  for (const data of packageSeeds) {
  
    const pkg = await prisma.package.upsert({
      where: { name: data.name },
      update: {},
                 
      create: data, 
    });
    packageMap[data.name] = pkg.id; 
   
  }

  console.log('✅ Seeding de pacotes concluído!');


  // --- SEED: POSIÇÕES DESEJADAS ---
  const desiredPositionMap: Record<string, string> = {};
  for (const data of desiredPositionData) {
    const position = await prisma.desiredPosition.upsert({
      where: { name: data.name },
      update: {},
      create: data,
    });
    desiredPositionMap[data.name] = position.id;
  }
  console.log('✅ Posições Desejadas criadas com sucesso!');

  // --- SEED: GÊNEROS ---
  const genderMap: Record<string, string> = {};
  for (const data of genderData) {
    const gender = await prisma.gender.upsert({
      where: { name: data.name },
      update: {},
      create: data,
    });
    genderMap[data.name] = gender.id;
  }
  console.log('✅ Gêneros criados com sucesso!');

  // --- SEED: ESTADOS CIVIS ---
  const maritalStatusMap: Record<string, string> = {};
  for (const data of maritalStatusData) {
    const status = await prisma.maritalStatus.upsert({
      where: { name: data.name },
      update: {},
      create: data,
    });
    maritalStatusMap[data.name] = status.id;
  }
  console.log('✅ Estados Civis criados com sucesso!');

  // --- SEED: GRAUS ACADÊMICOS ---
  const highestDegreeMap: Record<string, string> = {};
  for (const data of highestDegreeData) {
    const degree = await prisma.highestDegree.upsert({
      where: { name: data.name },
      update: {},
      create: data,
    });
    highestDegreeMap[data.name] = degree.id;
  }
  console.log('✅ Graus Acadêmicos criados com sucesso!');

  // --- SEED: CURSOS ---
  const courseMap: Record<string, string> = {};
  for (const data of courseData) {
    const course = await prisma.course.upsert({
      where: { name: data.name },
      update: {},
      create: data,
    });
    courseMap[data.name] = course.id;
  }
  console.log('✅ Cursos criados com sucesso!');

  // --- SEED: IDIOMAS ---
  const languageMap: Record<string, string> = {};
  for (const data of languageData) {
    const language = await prisma.language.upsert({
      where: { name: data.name },
      update: {},
      create: data,
    });
    languageMap[data.name] = language.id;
  }
  console.log('✅ Idiomas criados com sucesso!');

  // --- SEED: HABILIDADES ---
  const skillMap: Record<string, string> = {};
  for (const data of skillData) {
    const skill = await prisma.skill.upsert({
      where: { name: data.name },
      update: {},
      create: data,
    });
    skillMap[data.name] = skill.id;
  }
  console.log('✅ Habilidades criados com sucesso!');



  // --- SEED: NÍVEIS DE EXPERIÊNCIA ---
  const experienceLevelMap: Record<string, string> = {};
  for (const data of experienceLevelData) {
    const level = await prisma.experienceLevel.upsert({
      where: { name: data.name },
      update: {},
      create: data,
    });
    experienceLevelMap[data.name] = level.id;
  }
  console.log('✅ Níveis de experiência criados com sucesso!');

  // --- SEED: PERMISSÕES ---
  // ✅ Usando o array internalPermissions fornecido
  const permissionMap: Record<string, string> = {};
  for (const permissionData of internalPermissions) {
    const permission = await prisma.permission.upsert({
      where: { name: permissionData.name },
      update: { label: permissionData.label }, // Atualiza o label se já existir
      create: { name: permissionData.name, label: permissionData.label },
    });
    permissionMap[permissionData.name] = permission.id;
  }
  console.log('✅ Permissões criadas com sucesso!');


  // --- SEED: PERFIS ---
  // ✅ Nova seção para criar os perfis e associá-los às permissões
  for (const profileData of profilesData) {
    await prisma.profile.upsert({
      where: { name: profileData.name },
      update: {
        label: profileData.label,
        description: profileData.description,
        permissions: {
          set: profileData.permissions.map(pName => ({ name: pName })),
        },
      },
      create: {
        name: profileData.name,
        label: profileData.label,
        description: profileData.description,
        permissions: {
          connect: profileData.permissions.map(pName => ({ name: pName })),
        },
      },
    });
  }
  console.log('✅ Perfis de administrador criados e associados às permissões!');

  // --- SEED: ADMIN PADRÃO ---

// --- SEED: ADMIN PADRÃO ---
const defaultEmail = (process.env.DEFAULT_ADMIN_EMAIL || 'isaac.bunga@outlook.com').trim();
const defaultPassword = (process.env.DEFAULT_ADMIN_PASS || 'Pimentel##123!!').trim();

const existingAdmin = await prisma.adminUser.findUnique({
  where: { email: defaultEmail },
});

if (!existingAdmin) {
  const hashedPassword = await bcrypt.hash(defaultPassword, 10);
  
  // ✅ 1. Encontrar o perfil de 'GENERAL_ADMIN' pelo nome
  const generalAdminProfile = await prisma.profile.findUnique({
    where: { name: 'GENERAL_ADMIN' },
    select: { id: true } // Apenas selecione o ID para otimizar
  });
  
  // Se o perfil não for encontrado, é um erro crítico
  if (!generalAdminProfile) {
    throw new Error("Perfil 'GENERAL_ADMIN' não encontrado. Certifique-se de que a seção de perfis é executada primeiro.");
  }
  
  // ✅ 2. Criar o AdminUser e conectar o perfil usando o profileId
  await prisma.adminUser.create({
    data: {
      name: 'Isaac Bunga',
      numberphone: '900000000',
      identityNumber: '0000000000',
      genderId: genderMap['MALE'],
      birthDate: new Date('1990-01-01'),
      email: defaultEmail,
      avatar:"user.png",
      password: hashedPassword,
      isRoot:true,
      profileId: generalAdminProfile.id, 
    },
  });

  console.log(`✅ Admin padrão criado com perfil 'GENERAL_ADMIN': ${defaultEmail} / ${defaultPassword}`);
} else {
  console.log(`ℹ️ Admin padrão já existe: ${defaultEmail}`);
}
}

main()
  .catch((e) => {
    console.error('❌ Erro na seed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
