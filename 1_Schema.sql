-- ==========================================
-- STEP 1: THE NUKE (Resetting the database)
-- ==========================================
USE master;
GO

-- If the database exists, force close all connections and delete it
IF EXISTS (SELECT name FROM sys.databases WHERE name = N'CODManager')
BEGIN
    ALTER DATABASE CODManager SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE CODManager;
END
GO

-- ==========================================
-- STEP 2: THE REBUILD (Creating fresh)
-- ==========================================
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

-- 2. Buyers Table
CREATE TABLE Buyers (
    BuyerID INT IDENTITY(1,1) PRIMARY KEY,
    SellerID INT NOT NULL FOREIGN KEY REFERENCES Sellers(SellerID) ON DELETE CASCADE,
    FullName NVARCHAR(100) NOT NULL,
    Phone NVARCHAR(20) NOT NULL,
    Address NVARCHAR(255) NOT NULL,
    SellerBuyerNo INT NOT NULL,
    CONSTRAINT UQ_Buyers_SellerBuyerNo UNIQUE (SellerID, SellerBuyerNo),
    CONSTRAINT UQ_Buyers_SellerPhone UNIQUE (SellerID, Phone)
);

-- 2b. ClientUsers Table (portal login accounts per seller)
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

-- 3. Orders Table
CREATE TABLE Orders (
    OrderID INT IDENTITY(1,1) PRIMARY KEY,
    SellerID INT NOT NULL FOREIGN KEY REFERENCES Sellers(SellerID),
    BuyerID INT NOT NULL FOREIGN KEY REFERENCES Buyers(BuyerID),
    SellerOrderNo INT NOT NULL,
    BuyerName NVARCHAR(100) NULL,
    DeliveryAddress NVARCHAR(255) NULL,
    TotalAmount DECIMAL(10,2) NOT NULL,
    OrderStatus NVARCHAR(20) DEFAULT 'Pending' CHECK (OrderStatus IN ('Pending', 'Confirmed', 'Cancelled')),
    DeliveryStatus NVARCHAR(30) NULL CHECK (DeliveryStatus IN ('Pending', 'Delivered', 'Returned by buyer')),
    OrderDate DATETIME2 DEFAULT GETDATE(),
    CONSTRAINT UQ_Orders_SellerOrderNo UNIQUE (SellerID, SellerOrderNo)
);

-- 4. MessageLogs (The Weak Entity)
CREATE TABLE MessageLogs (
    LogID INT IDENTITY(1,1),
    OrderID INT NOT NULL,
    LogTime DATETIME2 DEFAULT GETDATE(),
    MessageContent NVARCHAR(255) NOT NULL,
    PRIMARY KEY (LogID, OrderID),
    FOREIGN KEY (OrderID) REFERENCES Orders(OrderID) ON DELETE CASCADE
);