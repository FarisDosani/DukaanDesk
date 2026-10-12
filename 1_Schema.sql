-- Fresh-install schema for DukaanDesk.
-- Safety: this script refuses to run when CODManager already exists.
-- Use 5_Migration.sql for an existing database; never drop production data.
USE master;
GO

IF EXISTS (SELECT name FROM sys.databases WHERE name = N'CODManager')
BEGIN
    THROW 50001, 'CODManager already exists. Aborting to preserve existing data; use 5_Migration.sql instead.', 1;
END
GO

CREATE DATABASE CODManager;
GO
USE CODManager;
GO

-- 1. Sellers Table
CREATE TABLE Sellers (
    SellerID INT IDENTITY(1,1) PRIMARY KEY,
    BusinessName NVARCHAR(100) NOT NULL,
    WhatsAppNumber NVARCHAR(20) UNIQUE NOT NULL,
    Email NVARCHAR(255) UNIQUE NOT NULL,
    DomainName NVARCHAR(120) UNIQUE NOT NULL
);

-- 2. Organizations (immutable SaaS tenant identity; one-to-one with legacy Sellers)
CREATE TABLE Organizations (
    OrganizationID UNIQUEIDENTIFIER ROWGUIDCOL NOT NULL
        CONSTRAINT DF_Organizations_OrganizationID DEFAULT NEWSEQUENTIALID(),
    LegacySellerID INT NOT NULL,
    OrganizationName NVARCHAR(100) NOT NULL,
    CreatedAt DATETIME2 NOT NULL CONSTRAINT DF_Organizations_CreatedAt DEFAULT GETDATE(),
    CONSTRAINT PK_Organizations PRIMARY KEY (OrganizationID),
    CONSTRAINT UQ_Organizations_LegacySellerID UNIQUE (LegacySellerID),
    CONSTRAINT FK_Organizations_Sellers FOREIGN KEY (LegacySellerID) REFERENCES Sellers(SellerID)
);

-- 3. Buyers Table
CREATE TABLE Buyers (
    BuyerID INT IDENTITY(1,1) PRIMARY KEY,
    SellerID INT NOT NULL FOREIGN KEY REFERENCES Sellers(SellerID) ON DELETE CASCADE,
    FullName NVARCHAR(100) NOT NULL,
    Phone NVARCHAR(20) NOT NULL,
    Address NVARCHAR(255) NOT NULL,
    SellerBuyerNo INT NOT NULL,
    CONSTRAINT UQ_Buyers_SellerBuyerNo UNIQUE (SellerID, SellerBuyerNo),
    CONSTRAINT UQ_Buyers_SellerPhone UNIQUE (SellerID, Phone),
    CONSTRAINT UQ_Buyers_SellerBuyerIdentity UNIQUE (SellerID, BuyerID)
);

-- 3b. ClientUsers Table (portal login accounts per seller)
CREATE TABLE ClientUsers (
    UserID INT IDENTITY(1,1) PRIMARY KEY,
    SellerID INT NOT NULL FOREIGN KEY REFERENCES Sellers(SellerID) ON DELETE CASCADE,
    Username NVARCHAR(100) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(255) NOT NULL,
    FailedAttempts INT NOT NULL DEFAULT 0,
    IsLocked BIT NOT NULL DEFAULT 0,
    LastFailedAt DATETIME2 NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT GETDATE()
);

-- 4. Orders Table
CREATE TABLE Orders (
    OrderID INT IDENTITY(1,1) PRIMARY KEY,
    SellerID INT NOT NULL FOREIGN KEY REFERENCES Sellers(SellerID),
    BuyerID INT NOT NULL FOREIGN KEY REFERENCES Buyers(BuyerID),
    SellerOrderNo INT NOT NULL,
    BuyerName NVARCHAR(100) NULL,
    DeliveryAddress NVARCHAR(255) NULL,
    TotalAmount DECIMAL(10,2) NOT NULL,
    OrderStatus NVARCHAR(20) NOT NULL DEFAULT 'Pending',
    DeliveryStatus NVARCHAR(30) NULL,
    OrderDate DATETIME2 NOT NULL DEFAULT GETDATE(),
    CONSTRAINT UQ_Orders_SellerOrderNo UNIQUE (SellerID, SellerOrderNo),
    CONSTRAINT CK_Orders_PositiveAmount CHECK (TotalAmount > 0),
    CONSTRAINT CK_Orders_AllowedOrderStatus CHECK (OrderStatus IN ('Pending', 'Confirmed', 'Cancelled')),
    CONSTRAINT CK_Orders_AllowedDeliveryStatus CHECK (DeliveryStatus IN ('Pending', 'Delivered', 'Returned by buyer')),
    CONSTRAINT CK_Orders_StateConsistency CHECK (
        (OrderStatus = 'Pending' AND DeliveryStatus IS NULL)
        OR (OrderStatus = 'Confirmed' AND DeliveryStatus IS NOT NULL)
        OR (OrderStatus = 'Cancelled' AND DeliveryStatus IS NULL)
    ),
    CONSTRAINT FK_Orders_SellerBuyer FOREIGN KEY (SellerID, BuyerID)
        REFERENCES Buyers(SellerID, BuyerID)
);

-- 5. MessageLogs (The Weak Entity)
CREATE TABLE MessageLogs (
    LogID INT IDENTITY(1,1),
    OrderID INT NOT NULL,
    LogTime DATETIME2 DEFAULT GETDATE(),
    MessageContent NVARCHAR(255) NOT NULL,
    PRIMARY KEY (LogID, OrderID),
    FOREIGN KEY (OrderID) REFERENCES Orders(OrderID) ON DELETE CASCADE
);
