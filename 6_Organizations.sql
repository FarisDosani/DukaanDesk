-- Phase 2.1 additive organization migration for an existing CODManager database.
-- Back up and run read-only preflight checks before executing this script manually.
-- This migration creates one immutable organization per existing seller and changes no
-- Sellers, ClientUsers, Buyers, Orders, or MessageLogs rows.
USE CODManager;
GO

SET XACT_ABORT ON;

BEGIN TRY
    BEGIN TRANSACTION;

    IF OBJECT_ID(N'dbo.Sellers', N'U') IS NULL
        THROW 50010, 'Sellers is missing. No organization migration changes were applied.', 1;

    IF OBJECT_ID(N'dbo.Organizations', N'U') IS NULL
    BEGIN
        CREATE TABLE dbo.Organizations (
            OrganizationID UNIQUEIDENTIFIER ROWGUIDCOL NOT NULL
                CONSTRAINT DF_Organizations_OrganizationID DEFAULT NEWSEQUENTIALID(),
            LegacySellerID INT NOT NULL,
            OrganizationName NVARCHAR(100) NOT NULL,
            CreatedAt DATETIME2 NOT NULL CONSTRAINT DF_Organizations_CreatedAt DEFAULT GETDATE(),
            CONSTRAINT PK_Organizations PRIMARY KEY (OrganizationID),
            CONSTRAINT UQ_Organizations_LegacySellerID UNIQUE (LegacySellerID),
            CONSTRAINT FK_Organizations_Sellers FOREIGN KEY (LegacySellerID)
                REFERENCES dbo.Sellers(SellerID)
        );
    END
    ELSE IF COL_LENGTH(N'dbo.Organizations', N'OrganizationID') IS NULL
         OR COL_LENGTH(N'dbo.Organizations', N'LegacySellerID') IS NULL
         OR COL_LENGTH(N'dbo.Organizations', N'OrganizationName') IS NULL
         OR COL_LENGTH(N'dbo.Organizations', N'CreatedAt') IS NULL
         OR NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = N'PK_Organizations')
         OR NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = N'UQ_Organizations_LegacySellerID')
         OR NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = N'FK_Organizations_Sellers')
        THROW 50011, 'An incompatible Organizations table already exists. No migration changes were applied.', 1;

    INSERT INTO dbo.Organizations (LegacySellerID, OrganizationName)
    SELECT S.SellerID, S.BusinessName
    FROM dbo.Sellers S
    WHERE NOT EXISTS (
        SELECT 1
        FROM dbo.Organizations Org
        WHERE Org.LegacySellerID = S.SellerID
    );

    IF EXISTS (
        SELECT 1
        FROM dbo.Sellers S
        LEFT JOIN dbo.Organizations Org ON Org.LegacySellerID = S.SellerID
        WHERE Org.OrganizationID IS NULL
    )
        THROW 50014, 'At least one seller is missing an organization mapping. Migration rolled back.', 1;

    IF EXISTS (
        SELECT LegacySellerID
        FROM dbo.Organizations
        GROUP BY LegacySellerID
        HAVING COUNT(*) <> 1
    )
        THROW 50015, 'Organization mappings are not one-to-one. Migration rolled back.', 1;

    EXEC(N'
        CREATE OR ALTER TRIGGER dbo.trg_Organizations_ImmutableIdentity
        ON dbo.Organizations
        AFTER UPDATE, DELETE
        AS
        BEGIN
            SET NOCOUNT ON;

            IF NOT EXISTS (SELECT 1 FROM inserted)
                THROW 50012, ''Organizations cannot be deleted; use a future lifecycle status instead.'', 1;

            IF UPDATE(OrganizationID) OR UPDATE(LegacySellerID)
                THROW 50013, ''OrganizationID and LegacySellerID are immutable.'', 1;
        END;
    ');

    COMMIT TRANSACTION;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    THROW;
END CATCH;
GO
