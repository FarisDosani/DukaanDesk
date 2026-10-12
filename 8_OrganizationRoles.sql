-- Phase 2.3 additive RBAC. Select the application DB explicitly; stop app writes first.
-- Founder evidence: the organization's sole legacy ClientUser, via the immutable mapping.
-- Multiple legacy accounts are ambiguous: leave unassigned for manual review, never guess.
SET XACT_ABORT ON;
SET NOCOUNT ON;
IF DB_NAME() IN ('master','model','msdb','tempdb')
    THROW 50030, 'Select an application database explicitly.', 1;
IF OBJECT_ID('dbo.OrganizationMemberships','U') IS NULL
    THROW 50031, 'Apply migration 7 first.', 1;
BEGIN TRY
    BEGIN TRANSACTION;
    IF OBJECT_ID('dbo.Roles','U') IS NULL
        CREATE TABLE dbo.Roles (
            RoleName NVARCHAR(20) NOT NULL CONSTRAINT PK_Roles PRIMARY KEY,
            CONSTRAINT CK_Roles_Name CHECK (RoleName IN ('Owner','Admin','Operations','Finance','Marketing','Support'))
        );
    DECLARE @NewPermissionTable BIT = 0;
    IF OBJECT_ID('dbo.RolePermissions','U') IS NULL
    BEGIN
        CREATE TABLE dbo.RolePermissions (
            RoleName NVARCHAR(20) NOT NULL,
            Permission NVARCHAR(40) NOT NULL,
            CONSTRAINT PK_RolePermissions PRIMARY KEY (RoleName, Permission),
            CONSTRAINT FK_RolePermissions_Roles FOREIGN KEY (RoleName) REFERENCES dbo.Roles(RoleName),
            CONSTRAINT CK_RolePermissions_Permission CHECK (Permission IN
                ('dashboard.view','summary.view','orders.decide','orders.delivery',
                 'organizations.switch','members.view','members.roles'))
        );
        SET @NewPermissionTable = 1;
    END;
    INSERT dbo.Roles (RoleName)
    SELECT V.RoleName FROM (VALUES ('Owner'),('Admin'),('Operations'),('Finance'),('Marketing'),('Support')) V(RoleName)
    WHERE NOT EXISTS (SELECT 1 FROM dbo.Roles R WHERE R.RoleName=V.RoleName);

    DECLARE @Policy TABLE (RoleName NVARCHAR(20), Permission NVARCHAR(40));
    INSERT @Policy VALUES
        ('Owner','dashboard.view'),('Owner','summary.view'),('Owner','orders.decide'),
        ('Owner','orders.delivery'),('Owner','organizations.switch'),('Owner','members.view'),('Owner','members.roles'),
        ('Admin','dashboard.view'),('Admin','summary.view'),('Admin','orders.decide'),
        ('Admin','orders.delivery'),('Admin','organizations.switch'),('Admin','members.view'),
        ('Operations','dashboard.view'),('Operations','orders.decide'),('Operations','orders.delivery'),('Operations','organizations.switch'),
        ('Finance','dashboard.view'),('Finance','summary.view'),('Finance','organizations.switch'),
        ('Marketing','dashboard.view'),('Marketing','summary.view'),('Marketing','organizations.switch'),
        ('Support','dashboard.view'),('Support','organizations.switch');
    -- Bootstrap policy once. Reruns validate rather than silently resurrect removed grants.
    IF @NewPermissionTable = 1
        INSERT dbo.RolePermissions SELECT RoleName, Permission FROM @Policy;
    IF EXISTS (SELECT RoleName, Permission FROM @Policy EXCEPT SELECT RoleName, Permission FROM dbo.RolePermissions)
       OR EXISTS (SELECT RoleName, Permission FROM dbo.RolePermissions EXCEPT SELECT RoleName, Permission FROM @Policy)
        THROW 50032, 'Role permission policy differs; review explicitly before migration.', 1;

    IF COL_LENGTH('dbo.OrganizationMemberships','RoleName') IS NULL
    BEGIN
        ALTER TABLE dbo.OrganizationMemberships ADD RoleName NVARCHAR(20) NULL;
        EXEC(N'ALTER TABLE dbo.OrganizationMemberships WITH CHECK ADD CONSTRAINT FK_Memberships_Roles
            FOREIGN KEY (RoleName) REFERENCES dbo.Roles(RoleName);');
        EXEC(N'UPDATE M SET RoleName = ''Owner''
            FROM dbo.OrganizationMemberships M
            JOIN dbo.Users U ON U.UserID=M.UserID
            JOIN dbo.ClientUsers CU ON CU.UserID=U.LegacyClientUserID
            JOIN dbo.Organizations O ON O.OrganizationID=M.OrganizationID AND O.LegacySellerID=CU.SellerID
            WHERE (SELECT COUNT(*) FROM dbo.ClientUsers C WHERE C.SellerID=CU.SellerID)=1;');
    END;
    IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name='FK_Memberships_Roles'
                   AND parent_object_id=OBJECT_ID('dbo.OrganizationMemberships') AND is_disabled=0 AND is_not_trusted=0)
        THROW 50033, 'Membership role constraint is missing or untrusted.', 1;
    COMMIT TRANSACTION;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    THROW;
END CATCH;
