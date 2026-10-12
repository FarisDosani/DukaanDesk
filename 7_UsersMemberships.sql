-- Phase 2.2. Run in an explicitly selected application database after migration 6.
-- No USE statement: the operator must select and verify the target database.
-- Stop application writes during migration. Back up existing deployments first.
-- Preflight only: run the SELECT/IF checks below before approving any DDL.
SET XACT_ABORT ON;
SET NOCOUNT ON;

IF DB_NAME() IN ('master', 'model', 'msdb', 'tempdb')
    THROW 50020, 'Select an application database explicitly.', 1;
IF OBJECT_ID(N'dbo.ClientUsers', N'U') IS NULL OR OBJECT_ID(N'dbo.Organizations', N'U') IS NULL
    THROW 50021, 'ClientUsers and Organizations are required.', 1;

BEGIN TRY
    BEGIN TRANSACTION;
    IF (OBJECT_ID(N'dbo.Users', N'U') IS NULL AND OBJECT_ID(N'dbo.OrganizationMemberships', N'U') IS NOT NULL)
       OR (OBJECT_ID(N'dbo.Users', N'U') IS NOT NULL AND OBJECT_ID(N'dbo.OrganizationMemberships', N'U') IS NULL)
        THROW 50025, 'Partial identity schema exists. Review it manually before continuing.', 1;
    -- Counts only: do not print email addresses or credential material.
    IF EXISTS (
        SELECT LOWER(LTRIM(RTRIM(S.Email)))
        FROM dbo.ClientUsers CU JOIN dbo.Sellers S ON S.SellerID = CU.SellerID
        GROUP BY LOWER(LTRIM(RTRIM(S.Email))) HAVING COUNT(*) > 1
    )
        THROW 50022, 'Ambiguous duplicate normalized emails: resolve ownership manually; no identities were merged.', 1;
    IF EXISTS (
        SELECT 1 FROM dbo.ClientUsers CU
        JOIN dbo.Sellers S ON S.SellerID = CU.SellerID
        LEFT JOIN dbo.Organizations O ON O.LegacySellerID = CU.SellerID
        WHERE O.OrganizationID IS NULL OR LEN(LTRIM(RTRIM(S.Email))) = 0
           OR CU.FailedAttempts < 0
    )
        THROW 50023, 'Invalid legacy identity or missing organization mapping.', 1;

    IF OBJECT_ID(N'dbo.Users', N'U') IS NULL
    BEGIN
        CREATE TABLE dbo.Users (
            UserID INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Users PRIMARY KEY,
            LegacyClientUserID INT NOT NULL CONSTRAINT UQ_Users_LegacyClientUser UNIQUE,
            Email NVARCHAR(255) NOT NULL,
            NormalizedEmail AS LOWER(LTRIM(RTRIM(Email))) PERSISTED,
            Username NVARCHAR(100) NOT NULL CONSTRAINT UQ_Users_Username UNIQUE,
            PasswordHash NVARCHAR(255) NOT NULL,
            FailedAttempts INT NOT NULL CONSTRAINT DF_Users_FailedAttempts DEFAULT 0,
            IsLocked BIT NOT NULL CONSTRAINT DF_Users_IsLocked DEFAULT 0,
            LastFailedAt DATETIME2 NULL,
            IsActive BIT NOT NULL CONSTRAINT DF_Users_IsActive DEFAULT 1,
            CreatedAt DATETIME2 NOT NULL CONSTRAINT DF_Users_CreatedAt DEFAULT GETDATE(),
            CONSTRAINT UQ_Users_NormalizedEmail UNIQUE (NormalizedEmail),
            CONSTRAINT CK_Users_Email CHECK (LEN(LTRIM(RTRIM(Email))) > 0),
            CONSTRAINT CK_Users_FailedAttempts CHECK (FailedAttempts >= 0),
            CONSTRAINT FK_Users_ClientUsers FOREIGN KEY (LegacyClientUserID) REFERENCES dbo.ClientUsers(UserID)
        );
    END;
    IF OBJECT_ID(N'dbo.OrganizationMemberships', N'U') IS NULL
    BEGIN
        CREATE TABLE dbo.OrganizationMemberships (
            UserID INT NOT NULL,
            OrganizationID UNIQUEIDENTIFIER NOT NULL,
            Status NVARCHAR(10) NOT NULL CONSTRAINT DF_Memberships_Status DEFAULT 'Inactive',
            CreatedAt DATETIME2 NOT NULL CONSTRAINT DF_Memberships_CreatedAt DEFAULT GETDATE(),
            CONSTRAINT PK_OrganizationMemberships PRIMARY KEY (UserID, OrganizationID),
            CONSTRAINT FK_Memberships_Users FOREIGN KEY (UserID) REFERENCES dbo.Users(UserID),
            CONSTRAINT FK_Memberships_Organizations FOREIGN KEY (OrganizationID) REFERENCES dbo.Organizations(OrganizationID),
            CONSTRAINT CK_Memberships_Status CHECK (Status IN ('Active', 'Inactive', 'Revoked'))
        );
    END;

    -- Refuse a drifted/incompatible schema rather than silently trusting weak constraints.
    IF (SELECT COUNT(*) FROM sys.key_constraints WHERE
        (parent_object_id = OBJECT_ID('dbo.Users') AND name IN
         ('PK_Users','UQ_Users_Username','UQ_Users_NormalizedEmail'))
        OR (parent_object_id = OBJECT_ID('dbo.OrganizationMemberships') AND name = 'PK_OrganizationMemberships')) <> 4
        OR NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id=OBJECT_ID('dbo.Users')
            AND is_unique=1 AND is_disabled=0 AND
            (name='UQ_Users_LegacyClientUser' OR (name='UX_Users_LegacyClientUser'
             AND has_filter=1 AND filter_definition='([LegacyClientUserID] IS NOT NULL)')))
        OR (SELECT COUNT(*) FROM sys.foreign_keys WHERE name IN
            ('FK_Users_ClientUsers','FK_Memberships_Users','FK_Memberships_Organizations')
            AND is_disabled = 0 AND is_not_trusted = 0) <> 3
        OR (SELECT COUNT(*) FROM sys.check_constraints WHERE name IN
            ('CK_Users_Email','CK_Users_FailedAttempts','CK_Memberships_Status')
            AND is_disabled = 0 AND is_not_trusted = 0) <> 3
        THROW 50026, 'Identity schema constraints are incompatible or untrusted.', 1;

    -- Import only unmapped legacy identities. Never overwrite newer authentication state
    -- or reactivate an existing membership on rerun.
    DECLARE @Imported TABLE (UserID INT, LegacyClientUserID INT);
    INSERT dbo.Users (LegacyClientUserID, Email, Username, PasswordHash,
                      FailedAttempts, IsLocked, LastFailedAt, CreatedAt)
    OUTPUT inserted.UserID, inserted.LegacyClientUserID INTO @Imported
    SELECT CU.UserID, LOWER(LTRIM(RTRIM(S.Email))), CU.Username, CU.PasswordHash,
           CU.FailedAttempts, CU.IsLocked, CU.LastFailedAt, CU.CreatedAt
    FROM dbo.ClientUsers CU JOIN dbo.Sellers S ON S.SellerID = CU.SellerID
    WHERE NOT EXISTS (SELECT 1 FROM dbo.Users U WHERE U.LegacyClientUserID = CU.UserID);

    INSERT dbo.OrganizationMemberships (UserID, OrganizationID, Status)
    SELECT I.UserID, O.OrganizationID, 'Active'
    FROM @Imported I JOIN dbo.ClientUsers CU ON CU.UserID = I.LegacyClientUserID
    JOIN dbo.Organizations O ON O.LegacySellerID = CU.SellerID;

    EXEC(N'CREATE OR ALTER TRIGGER dbo.trg_Users_ImmutableIdentity ON dbo.Users AFTER UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        IF UPDATE(UserID) OR UPDATE(LegacyClientUserID)
            THROW 50024, ''User identity and legacy mapping are immutable.'', 1;
    END;');
    COMMIT TRANSACTION;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    THROW;
END CATCH;
