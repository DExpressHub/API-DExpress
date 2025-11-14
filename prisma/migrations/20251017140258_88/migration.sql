/*
  Warnings:

  - You are about to drop the column `userId` on the `Notification` table. All the data in the column will be lost.

*/
-- DropForeignKey
ALTER TABLE "Notification" DROP CONSTRAINT "Notification_userId_fkey";

-- AlterTable
ALTER TABLE "Notification" DROP COLUMN "userId",
ADD COLUMN     "clientProfileId" TEXT,
ADD COLUMN     "clinteCompanyProfileId" TEXT;

-- CreateTable
CREATE TABLE "PasswordResetToken" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "used" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PasswordResetToken_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "PasswordResetToken_token_key" ON "PasswordResetToken"("token");

-- AddForeignKey
ALTER TABLE "PasswordResetToken" ADD CONSTRAINT "PasswordResetToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "AdminUser"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_clientProfileId_fkey" FOREIGN KEY ("clientProfileId") REFERENCES "ClientProfile"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_clinteCompanyProfileId_fkey" FOREIGN KEY ("clinteCompanyProfileId") REFERENCES "ClientCompanyProfile"("id") ON DELETE SET NULL ON UPDATE CASCADE;
