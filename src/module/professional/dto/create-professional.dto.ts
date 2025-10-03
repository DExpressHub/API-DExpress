import {
  IsString,
  IsUUID,
  IsArray,
  IsOptional,
  IsBoolean,
  IsEmail,
  IsNumber,
  IsDateString,
  ValidateNested,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsValidEmail } from 'src/common/validators/is-valid-email';
import { CreateLocationDto } from 'src/module/shared/location/dto/create-location.dto';

export class CreateProfessionalDto {
  @ApiProperty({ example: 'Maria Joaquina', description: 'Nome completo do profissional' })
  @IsString()
  fullName: string;

  @ApiProperty({ example: 'maria@example.com', description: 'Email do profissional' })
  @IsEmail()
   @IsValidEmail() 
  email: string;

  @ApiProperty({ example: '+244912345678', description: 'Telefone do profissional' })
  @IsString()
  phoneNumber: string;

  @ApiProperty({ example: '987654321LA044', description: 'Número de Identificação (BI ou Passaporte)', required: false })
  @IsOptional()
  @IsString()
  identityNumber?: string;



  @ApiProperty({ example: 'uuid-do-nivel-experiencia', description: 'ID do nível de experiência' })
  @IsUUID()
  experienceLevelId: string;

  @ApiProperty({ example: 'a2f648f5-6dcd-4e3a-bdd7-26b814d6f5b6', description: 'ID da candidatura aprovada', required: false })
  @IsOptional()
  @IsUUID()
  jobApplicationId?: string;

  @ApiProperty({ example: 'Sou responsável, pontual e tenho experiência com crianças.' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiProperty({ example: '2025-09-01T12:00:00Z', description: 'Data esperada de disponibilidade', required: false })
  @IsOptional()
  @IsDateString()
  expectedAvailability?: string;

  @ApiProperty({ example: true, description: 'Possui registro criminal?' })
  @IsBoolean()
  hasCriminalRecord: boolean;

  @ApiProperty({ example: true, description: 'Possui atestado médico?' })
  @IsBoolean()
  hasMedicalCertificate: boolean;

  @ApiProperty({ example: true, description: 'Possui certificado de formação?' })
  @IsBoolean()
  hasTrainingCertificate: boolean;

  @ApiProperty({ example: '76c1e5b4-2f33-4b90-8f83-874cbd02d9e5', description: 'ID da localização atual' })
  @IsUUID()
  @IsOptional()
  locationId?: string;

  @ApiProperty({ example: '76c1e5b4-2f33-4b90-8f83-874cbd02d9e5', description: 'ID do gênero' })
  @IsUUID()
  genderId: string;

  @ApiProperty({ example: '1998-05-10T12:00:00Z', description: 'Data de nascimento' })
  @IsDateString()
  birthDate: string;

  @ApiProperty({ example: '76c1e5b4-2f33-4b90-8f83-874cbd02d9e5', description: 'ID do estado civil', required: false })
  @IsOptional()
  @IsUUID()
  maritalStatusId?: string;

  @ApiProperty({ example: true, description: 'Possui filhos?' })
  @IsBoolean()
  hasChildren: boolean;

 @ApiProperty({ example: false, required: false })
@IsOptional()
@IsBoolean()
knownDiseases?: boolean;

  @ApiProperty({ example: '76c1e5b4-2f33-4b90-8f83-874cbd02d9e5', description: 'ID do cargo/posição desejada' })
  @IsUUID()
  desiredPositionId: string;

  @ApiProperty({ example: 50000, description: 'Pretensão salarial em Kz' })
  @IsNumber()
  @Type(() => Number)
  expectedSalary: number;

  @ApiProperty({ example: '76c1e5b4-2f33-4b90-8f83-874cbd02d9e5', description: 'ID do grau acadêmico mais elevado', required: false })
  @IsOptional()
  @IsUUID()
  highestDegreeId?: string;

  @ApiProperty({ example: ['id-da-experiencia-1', 'id-da-experiencia-2'], description: 'Lista de IDs de experiências profissionais existentes', required: false })
  @IsOptional()
  @IsArray()
  @IsUUID('4', { each: true })
  experienceIds?: string[];

  @ApiProperty({ example: ['id-do-curso-1', 'id-do-curso-2'], description: 'Lista de IDs de cursos' })
  @IsArray()
  @IsUUID('4', { each: true })
  courseIds: string[];

  @ApiProperty({ example: ['id-do-idioma-1', 'id-do-idioma-2'], description: 'Lista de IDs de idiomas' })
  @IsArray()
  @IsUUID('4', { each: true })
  languageIds: string[];

  @ApiProperty({ example: ['id-da-habilidade-1', 'id-da-habilidade-2'], description: 'Lista de IDs de habilidades' })
  @IsArray()
  @IsUUID('4', { each: true })
  skillIds: string[];
 
  @IsOptional()
  profileImage?: any;


  @ValidateNested()
  @Type(() => CreateLocationDto)
  location?: CreateLocationDto;
}