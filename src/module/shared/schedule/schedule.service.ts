import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { AuditLogService } from '../auditLog/auditLog.service';

@Injectable()
export class ScheduleService {
  private readonly logger = new Logger(ScheduleService.name);

  constructor(
    private prisma: PrismaService,
    private auditLogService: AuditLogService,
  ) { }
  @Cron('0 0 * * *')
  async handleContractExpiration() {
    const now = new Date();
    const contractsToExpire = await this.prisma.contract.findMany({
      where: {
        endDate: { lte: now },
        status: 'ACTIVE',
      },
      select: {
        id: true,
        contractNumber: true,
        professionalId: true,
        contractPackegeProfissional: {
          select: {
            professionalId: true,
          },
        },
      }
    });
    // pegar todos os profissionais desses contratos
    const professionalIds = [
      ...contractsToExpire
        .map(c => c.professionalId)
        .filter((id): id is string => id !== null),

      ...contractsToExpire.flatMap(c =>
        c.contractPackegeProfissional.map(cp => cp.professionalId)
      ),
    ].filter((id, idx, arr) => id !== null && arr.indexOf(id) === idx);
    if (contractsToExpire.length === 0) {
      this.logger.log('Nenhum contrato expirado encontrado.');
      return;
    }
    // 1) Atualiza todos de uma vez
    await this.prisma.contract.updateMany({
      where: { id: { in: contractsToExpire.map((c) => c.id) } },
      data: { status: 'EXPIRED' },
    });
    if (professionalIds.length > 0) {
      await this.prisma.professional.updateMany({
        where: { id: { in: professionalIds } },
        data: { isAvailable: true },
      });
    }
    for (const contract of contractsToExpire) {
      await this.auditLogService.createLog({
        action: 'EXPIRE_CONTRACT',
        entity: 'Contract',
        description: `Scheduler atualizou o contrato ${contract.contractNumber} para "EXPIRED"`,
        status: 'SUCCESS',
        source: 'CRON_JOB',
      });
    }
    this.logger.log(
      `Contracts automatically updated: ${contractsToExpire.length} contratos`
    );
  }


}
