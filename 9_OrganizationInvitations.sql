-- Phase 2.4. Select the application database explicitly; stop app writes first.
-- Non-destructive: existing identity values and all memberships remain unchanged.
-- The legacy unique constraint is replaced transactionally by a filtered unique
-- index so multiple employees can have NULL legacy links. The FK and immutable
-- identity trigger remain in force. No identities are merged or remapped.
SET XACT_ABORT ON;
SET NOCOUNT ON;
IF DB_NAME() IN ('master','model','msdb','tempdb')
    THROW 50040, 'Select an application database explicitly.', 1;
IF OBJECT_ID('dbo.Users','U') IS NULL OR COL_LENGTH('dbo.OrganizationMemberships','RoleName') IS NULL
    THROW 50041, 'Apply migrations 7 and 8 first.', 1;
IF EXISTS (SELECT LegacyClientUserID FROM dbo.Users WHERE LegacyClientUserID IS NOT NULL
           GROUP BY LegacyClientUserID HAVING COUNT(*)>1)
    THROW 50042, 'Duplicate legacy mappings; manual review required.', 1;
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name='FK_Users_ClientUsers'
               AND is_disabled=0 AND is_not_trusted=0)
    THROW 50043, 'Legacy identity foreign key is not trusted.', 1;
BEGIN TRY
    BEGIN TRANSACTION;
    IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id=OBJECT_ID('dbo.Users')
               AND name='LegacyClientUserID' AND is_nullable=0)
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE parent_object_id=OBJECT_ID('dbo.Users')
                       AND name='UQ_Users_LegacyClientUser')
            THROW 50044, 'Unexpected legacy identity constraint; review schema.', 1;
        ALTER TABLE dbo.Users DROP CONSTRAINT UQ_Users_LegacyClientUser;
        ALTER TABLE dbo.Users ALTER COLUMN LegacyClientUserID INT NULL;
        CREATE UNIQUE INDEX UX_Users_LegacyClientUser ON dbo.Users(LegacyClientUserID)
            WHERE LegacyClientUserID IS NOT NULL;
    END;
    IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id=OBJECT_ID('dbo.Users')
        AND name='UX_Users_LegacyClientUser' AND is_unique=1 AND is_disabled=0
        AND has_filter=1 AND filter_definition='([LegacyClientUserID] IS NOT NULL)')
        THROW 50044, 'Filtered legacy identity index missing or incompatible.', 1;
    IF OBJECT_ID('dbo.OrganizationInvitations','U') IS NULL
    BEGIN
        CREATE TABLE dbo.OrganizationInvitations (
            InvitationID UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID()
                CONSTRAINT PK_OrganizationInvitations PRIMARY KEY,
            OrganizationID UNIQUEIDENTIFIER NOT NULL,
            Email NVARCHAR(255) NOT NULL,
            RoleName NVARCHAR(20) NOT NULL,
            TokenHash CHAR(64) NOT NULL CONSTRAINT UQ_Invitations_TokenHash UNIQUE,
            Status NVARCHAR(10) NOT NULL DEFAULT 'Pending',
            CreatedByUserID INT NOT NULL,
            CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
            ExpiresAt DATETIME2 NOT NULL,
            AcceptedByUserID INT NULL,
            AcceptedAt DATETIME2 NULL,
            VerificationHash CHAR(64) NULL,
            VerificationExpiresAt DATETIME2 NULL,
            VerificationSentAt DATETIME2 NULL,
            CONSTRAINT FK_Invitations_Organizations FOREIGN KEY(OrganizationID) REFERENCES dbo.Organizations(OrganizationID),
            CONSTRAINT FK_Invitations_Roles FOREIGN KEY(RoleName) REFERENCES dbo.Roles(RoleName),
            CONSTRAINT FK_Invitations_Creator FOREIGN KEY(CreatedByUserID) REFERENCES dbo.Users(UserID),
            CONSTRAINT FK_Invitations_Acceptor FOREIGN KEY(AcceptedByUserID) REFERENCES dbo.Users(UserID),
            CONSTRAINT CK_Invitations_Role CHECK(RoleName IN ('Admin','Operations','Finance','Marketing','Support')),
            CONSTRAINT CK_Invitations_Email CHECK(Email=LOWER(LTRIM(RTRIM(Email))) AND LEN(Email)>3),
            CONSTRAINT CK_Invitations_Status CHECK(Status IN ('Pending','Accepted','Expired','Revoked')),
            CONSTRAINT CK_Invitations_Expiry CHECK(ExpiresAt>CreatedAt),
            CONSTRAINT CK_Invitations_Accepted CHECK(
                (Status='Accepted' AND AcceptedByUserID IS NOT NULL AND AcceptedAt IS NOT NULL)
                OR (Status<>'Accepted' AND AcceptedByUserID IS NULL AND AcceptedAt IS NULL)),
            CONSTRAINT CK_Invitations_Verification CHECK(
                (VerificationHash IS NULL AND VerificationExpiresAt IS NULL)
                OR (VerificationHash IS NOT NULL AND VerificationExpiresAt IS NOT NULL))
        );
        CREATE UNIQUE INDEX UX_Invitations_Pending ON dbo.OrganizationInvitations(OrganizationID,Email)
            WHERE Status='Pending';
    END;
    IF (SELECT COUNT(*) FROM sys.foreign_keys WHERE parent_object_id=OBJECT_ID('dbo.OrganizationInvitations')
        AND is_disabled=0 AND is_not_trusted=0)<>4
       OR (SELECT COUNT(*) FROM sys.check_constraints WHERE parent_object_id=OBJECT_ID('dbo.OrganizationInvitations')
        AND is_disabled=0 AND is_not_trusted=0)<>6
        THROW 50045, 'Invitation constraints missing or untrusted.', 1;
    COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT>0 ROLLBACK;
    THROW;
END CATCH;
